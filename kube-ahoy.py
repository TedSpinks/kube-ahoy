#!/usr/bin/env python3

"""
Kube Ahoy! Easily manage your kubeconfig for a whole fleet of Kubernetes clusters.
Original script and detailed README live here: https://github.com/TedSpinks/kube-ahoy

Testing:
- Python 3.7.7 on macOS
- Python 3.6.9 on Ubuntu
- I don't think this will run in Windows, as the curses library isn't the same

One of the goals of this script was to be a single, self-contained file. To that end, the following 
standard libraries and command line tools were used instead of libraries that required a pip install:
- 'json' library instead of the PyYAML library
- 'urllib' library instead of the 'requests' library
- input() function instead of the 'readchar' library
- kubectl command instead of the 'kubernetes' library
"""

import os
import math
import logging
import argparse
from argparse import RawTextHelpFormatter # Preserve newlines
import curses # Control the terminal screen; not in Windows
import json
import subprocess
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import ssl  # To turn off cert checking in urllib
import base64  # For HTTP basic auth

class Kubeconfig(object):
    """Manages the local kubeconfig and its contexts"""
    kubeconfig_file = None  # optional, alternative kubeconfig file
    kubeconfig_data = None  # dict containing the active kubeconfig
    current_context = None  # name of the current context

    def __init__(self, kubeconfig_file=None):
        self.logger = logging.getLogger(__name__)
        self.kubeconfig_file = kubeconfig_file
        self.__load_kubeconfig()
        self.current_context = self.kubeconfig_data['current-context']
        logging.debug("Current context: {}".format(self.current_context))

    def __safe_len(self, object):
        if object == None: return 0
        return len(object)

    def __load_kubeconfig(self):
        """ Read the kubeconfig into a dictionary. Uses json as opposed to yaml,
        since json is part of the python standard library. kubectl should always
        produce valid json with the correct top-level fields, even if the kubeconfig
        file doesn't exist (yet)."""
        cmd = "kubectl config view -o json"
        if self.kubeconfig_file: cmd += " --kubeconfig {}".format(kubeconfig_file)
        output, returncode = self.__run_cmd(cmd)
        self.kubeconfig_data = json.loads(output)
        self.logger.debug( "Retrieved: {} context(s), {} cluster(s), {} user(s)".format (
            self.__safe_len(self.kubeconfig_data['contexts']), 
            self.__safe_len(self.kubeconfig_data['clusters']), 
            self.__safe_len(self.kubeconfig_data['users'])
        ))

    def __run_cmd(self, cmd, input=None, fail_on_non_zero=True, no_log_cmd=False):
        """Run a command in the OS"""
        result = subprocess.run(cmd.split(), 
            input=input, 
            stdout=subprocess.PIPE,   # send stderr to stdout
            stderr=subprocess.STDOUT)
        output = result.stdout.decode('utf-8').rstrip()
        returncode = result.returncode
        if no_log_cmd: cmd = "[REDACTED]"
        summary = "\n  Command: ".format(cmd) + \
                  "\n  Return code: {}".format(returncode) + \
                  "\n  Output:\n{}".format(output)
        if fail_on_non_zero: assert(returncode == 0), summary
        self.logger.debug(summary)
        return output, returncode

    def __get_item_or_items(self, type, name=None):
        """Return either a list of item dictionaries, or if name is specified
        then return that single dictionary (not in a list)"""
        assert (type in ['clusters', 'users', 'contexts']), \
            "type arg must be one of: clusters, users, context"
        if not name:
            return self.kubeconfig_data[type]
        else:
            for item in self.kubeconfig_data[type]:
                if item['name'] == name: return item
        return None

    def get_contexts(self, name=None):
        """Return either a list, or if name is specified a single dict item"""
        return self.__get_item_or_items('contexts', name)

    def get_clusters(self, name=None):
        """Return either a list, or if name is specified a single dict item"""
        return self.__get_item_or_items('clusters', name)

    def get_users(self, name=None):
        """Return either a list, or if name is specified a single dict item"""
        return self.__get_item_or_items('users', name)

    def exists_in(self, obj_name, obj_type):
        assert (obj_type in ['contexts', 'clusters', 'users']), \
            "incorrect obj_type '{}', must be one of: context, cluster, user".format(obj_type)
        for object in self.kubeconfig_data[obj_type]:
            if object['name'] == obj_name: return True
        return False

    def use_context(self, context_name):
        """Make the specified context the current context"""
        cmd = "kubectl config use-context " + context_name
        if self.kubeconfig_file: cmd += " --kubeconfig=" + kubeconfig_file
        self.__run_cmd(cmd)

    def set_context(self, context, cluster=None, user=None, namespace=None):
        """Update or create the specified context with the specified fields"""
        assert (cluster or user or namespace), \
            "set_context() requires at least one of: cluster, user, namespace"
        cmd = "kubectl config set-context " + context
        if cluster: cmd += " --cluster=" + cluster
        if user: cmd += " --user=" + user
        if namespace: cmd += " --namespace=" + namespace
        if self.kubeconfig_file: cmd += " --kubeconfig=" + kubeconfig_file
        self.__run_cmd(cmd)

    def set_cluster(self, cluster_name, cluster_url, insecure=False):
        """Update or create the specified cluster with the specified fields"""
        cmd = "kubectl config set-cluster {} --server={}".format(cluster_name, cluster_url)
        if insecure: cmd += " --insecure-skip-tls-verify=true"
        if self.kubeconfig_file: cmd += " --kubeconfig=" + kubeconfig_file
        self.__run_cmd(cmd)

    def set_user(self, user_name, token=None, username=None, password=None):
        """Update or create the specified user with the specified fields"""
        assert (token or (username and password)), \
            "set_user() requires at least one of: token, username+password"
        cmd = "kubectl config set-credentials " + user_name
        if self.kubeconfig_file: cmd += " --kubeconfig=" + kubeconfig_file
        if token: 
            cmd += " --token=" + token
            self.__run_cmd(cmd)
        else:
            cmd += " --username={} --password={}".format(username, password)
            self.__run_cmd(cmd, no_log_cmd=True)

    def is_namespace_valid(self, namespace):
        """Check whether the namespace is available in the current context"""
        cmd = "kubectl get ns {}".format(namespace)
        if self.kubeconfig_file: cmd += " --kubeconfig=" + kubeconfig_file
        output, returncode = self.__run_cmd(cmd, fail_on_non_zero=False)
        if returncode == 0: return True
        else: return False

    def is_context_openshift(self, context_name):
        """Checks for OpenShift-style (oc login) context naming convention:
        [namespace]/<cluster>/<username>"""
        name_parts = context_name.split('/')
        true_msg = "Context '{}' conforms to OpenShift-style naming convention".format(context_name)
        false_msg = "Context '{}' does not conform to OpenShift-style naming convention".format(context_name)
        if len(name_parts) != 3: 
            logging.debug(false_msg)
            return False
        # Look up the context in kubeconfig, and make sure its fields match the name parts
        for context in self.kubeconfig_data['contexts']:
            if context['name'] == context_name:
                if context['context']['cluster'] != name_parts[1]:
                    logging.debug(false_msg)
                    return False
                # user naming convention is <username>/<cluster>
                username = context['context']['user'].split('/')[0]
                if username != name_parts[2]: 
                    logging.debug(false_msg)
                    return False
                break
        logging.debug(true_msg)
        return True

    def search_objects(self, obj_type, fields_to_match):
        """fields_to_find should be a dict with the key:value pairs to look for"""
        assert (obj_type in ['contexts', 'clusters', 'users']), \
            "incorrect obj_type '{}', must be one of: context, cluster, user".format(obj_type)
        search_items = []
        # Loop through all objects
        for object in self.kubeconfig_data[obj_type]:
            singular_type = obj_type.rstrip('s')
            match = True  # Tracks whether this object matches ALL the search fiekds
            # compare all the fields of this object...
            for obj_field in object[singular_type]:
                # ...to all the fields of the match criteria
                for match_field in fields_to_match:
                    if obj_field == match_field and object[singular_type][obj_field] != fields_to_match[obj_field]:
                        match = False
                        break
                if not match: break
            if match: search_items.append(object)
        return search_items

    def summarize_context(self, context_name, indent_fields=2):
        """Render the context obj in a string that looks nice, for printing on-screen"""
        for context in self.kubeconfig_data['contexts']:
            if context['name'] == context_name:
                summary = "context: '" + context['name'] + "'\n".ljust(indent_fields+2)
                summary += "cluster: '" + context['context']['cluster'] + "'\n".ljust(indent_fields+2)
                summary += "user: '" + context['context']['user'] + "'\n".ljust(indent_fields+2)
                # namespace is an optional field within a context
                if "namespace" in context['context']:
                    namespace = context['context']['namespace']
                else: namespace = ""
                summary += "namespace: '" + namespace + "'"
                break
        return summary

#### end of class Kubeconfig()


def get_args():
    desc = "examples:\n\n" + \
        "  # Change contexts by following interactive prompts\n" + \
        "  %(prog)s --context\n\n" + \
        "  # Interactively login to a cluster with a token, and save login to your kubeconfig\n" + \
        "  %(prog)s --login\n\n" + \
        "  # Change to a different namespace\n" + \
        "  %(prog)s -n my-awesome-namespace"
    kubeconfig_help = "path to a specific kubeconfig file to use; will be created if it doesn't exist"
    login_help = "add a new cluster/user/context to kubeconfig, via prompts"
    ctx_help = "change to a different cluster/context in kubeconfig, via prompts"
    ns_help = "change to a different namespace in the current cluster"
    parser = argparse.ArgumentParser(description=desc, 
        formatter_class=RawTextHelpFormatter)  # Preserve newlines
    parser.add_argument('-d','--debug', action='store_true', help="enable debug-level logging")
    parser.add_argument('--kubeconfig', metavar='<filepath>', action='store', help=kubeconfig_help)
    pick_one = parser.add_mutually_exclusive_group(required=False)
    pick_one.add_argument('-l','--login', action='store_true', help=login_help)
    pick_one.add_argument('-c','--context', action='store_true', help=ctx_help)
    pick_one.add_argument('-n','--namespace', metavar='<name>', action='store', help=ns_help)
    return parser.parse_args()

def get_users_of_cluster(cluster_name, kubeconfig):
    #### Get all the contexts of the specified cluster
    fields_to_match = {'cluster': cluster_name}
    contexts = kubeconfig.search_objects('contexts', fields_to_match)
    #### Read the user (name) from each context, and look up the user object
    users = []
    for ctx in contexts:
        user_name = ctx['context']['user']
        user_obj = kubeconfig.get_users(user_name)
        if user_obj not in users:
            users.append(user_obj)
    return users

def get_matching_contexts(cluster_name, user_name, kubeconfig):
    """Get all contexts with the specifid cluster and user, and return
    them in a list of dicts formatted for prompt_user_for_list_choice()"""
    fields_to_match = {
        'cluster': cluster_name,
        'user': user_name
    }
    contexts = kubeconfig.search_objects('contexts', fields_to_match)
    # prompt_user_for_list_choice(), which consumes this function's output,
    # can only render 1 level of fields. So we're bringing the 'namespace' 
    # field up to the same level as 'name'
    flattened_contexts = []
    for ctx in contexts:
        # namespace is an optional field within a context
        if "namespace" in ctx['context']:
            namespace = ctx['context']['namespace']
        else: namespace = ""
        new_ctx = {
            'name': ctx['name'],
            'namespace': namespace
        }
        flattened_contexts.append(new_ctx)
    return flattened_contexts

def start_curses_screen():
    """Initialize a curses object to be able to control the terminal screen"""
    screen = curses.initscr()
    #curses.cbreak()      # Don't require ENTER to read keystrokes
    #curses.keypad(True)  # Process keypad as special keys (ex: curses.KEY_LEFT)
    #curses.noecho()      # Don't echo keystrokes
    return screen

def end_curses_screen(screen):
    """Undo changes made by start_curses_screen() and release the terminal screen. If
    this script ends before calling this function, then your terminal will get wonky!"""
    curses.nocbreak()
    screen.keypad(False)
    curses.echo()
    curses.endwin()

def confirm_in_curses(msg, enter=False):
    """Prints message and prompt user for Y or N + ENTER. Use in conjunction
    with other full-screen curses functions, to keep the same look+feel."""
    screen = start_curses_screen()
    confirmed = False
    while True:
        screen.erase()
        screen.addstr(msg)
        screen.refresh()
        user_choice = screen.getstr(1).decode('UTF-8')
        if user_choice.lower() == 'y': confirmed = True; break
        if user_choice.lower() == 'n': confirmed = False; break
        if user_choice == "": confirmed = enter; break
    end_curses_screen(screen)
    return confirmed

def confirm(msg, enter=False):
    """Prints message and prompt user for Y or N, followed by ENTER"""
    while True:
        response = input(msg)
        if response == "": return enter
        if response.lower() == "y": return True
        if response.lower() == "n": return False

def is_str_an_int_within_range(str_to_check, range_min, range_max):
    """Makes sure that the string, str_to_check, represents a valid int,
    and that the int falls within the specified range"""
    try: 
        converted_int = int(str_to_check)
    except ValueError:
        return False  # the string doesn't represent an int
    if converted_int < range_min: return False
    if converted_int > range_max: return False
    return True

def compose_menu_choices(list, first_list_index, num_items_on_screen, fields_to_print):
    """Takes a subset of the list to compose the next screen of menu choices"""
    logging.debug(num_items_on_screen)
    choice_num = 1  # Numbering of choices for each screen always starts at 1
    menu = ""
    for i in range(first_list_index, first_list_index+num_items_on_screen):
        #if menu != "": menu += "\n"
        item = list[i]
        menu_line = "[{}] ".format(str(choice_num).zfill(2))  # Format choice number
        for field in fields_to_print:
            menu_line += "{}: '{}'  ".format(field, item[field])
        menu += menu_line + "\n"
        choice_num += 1
    return menu

def test_k8s_connectivity(url, token=None, username=None, password=None, insecure=False):
    """Test connecting to the cluster URL via the specified auth method,
    authentication is optional"""
    timeout_secs = 10
    url += "/api"
    headers = None
    if token:
        headers = { 'Authorization' : "Bearer " + token }
        req = Request(url, None, headers)
        logging.debug("Attempting to connect this URL with token auth:\n'{}'".format(url))
    elif username and password:
        logging.warning("I haven't tested basic auth yet!")
        # base64 encode the username:password for Basic auth
        creds_text = "{}:{}".format(username, password)
        creds_bytes = creds_text.encode('ascii')
        base64_bytes = base64.b64encode(creds_bytes)
        base64_text = base64_bytes.decode('ascii')
        headers = { 'Authorization' : "Basic " + base64_text }
        req = Request(url, None, headers)
        logging.debug("Attempting to connect this URL with basic auth:\n'{}'".format(url))
    else:
        logging.debug("Attempting to connect this URL with no auth:\n'{}'".format(url))
        req = Request(url)
    try:
        print(insecure)
        if insecure:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            logging.debug("Skipping TLS verification")
            response = urlopen(req, None, timeout_secs, context=ssl_ctx)
        else:
            response = urlopen(req, None, timeout_secs)  # Attempt the connection!
        debug_msg = str(response.read())  # Some JSON text about the cluster
        if debug_msg.find("serverAddressByClientCIDRs") != -1: success = True
        else: success = False
    except HTTPError as e:
        success = False
        debug_msg = "The server responder with error code {}".format(e.code)
    except URLError as e:
        success = False
        debug_msg = "Could not reach server. Reason: {}".format(e.reason)
    if success: logging.debug(debug_msg)
    else: logging.error(debug_msg)
    return success

def prompt_user_for_list_choice(list_item_singular, list, fields_to_print=['name'], prompt_msg = ""):
    """Present a full-screen menu to the user. The menu items are comprised of the input list of
    dictionaries, and can span multiple screens. By default only a dictionary's 'name' field is
    printed in its menu item, since all kubeconfig objects have that field. Returns the list index 
    of the user's choice."""
    if not prompt_msg: prompt_msg = "Which {} do you want to connect to?\n".format(list_item_singular)
    #### Figure out screen/menu geometry
    screen = start_curses_screen()
    max_lines_on_screen = curses.LINES - 1
    max_choices_per_screen = max_lines_on_screen - 3  # Title + Navigation + User Prompt = 3
    num_items = len(list)  # Total number of items; can span multiple screens
    screen_index = 0  # When list spans multiple screens, this is the screen number
    max_screen_index = math.ceil(num_items / max_choices_per_screen) - 1
    # 14 11 21 0 1
    #### Screen refresh loop
    while True:
        screen.erase()
        screen.addstr(prompt_msg)
        #### Choose a subset of the list to compose the next screen
        # Each screen except the last one has the max number of choices
        if screen_index != max_screen_index: 
            num_items_on_screen = max_choices_per_screen
        # The last screen has the remainder (the same math also works when only 1 screen)
        else: num_items_on_screen = num_items % max_choices_per_screen
        # Advance the list index for the current screen
        first_list_index = screen_index * max_choices_per_screen
        menu = compose_menu_choices(list, first_list_index, num_items_on_screen, fields_to_print)
        screen.addstr(menu)
        #### Compose navigation choices
        nav_choices = ""
        if screen_index < max_screen_index: nav_choices += "[N]ext screen, "
        if screen_index > 0: nav_choices += "[P]revious screen, "
        nav_choices += "[Q]uit\n\nMake your choice and press ENTER: "
        screen.addstr(nav_choices)
        #### Render screen and get user's choice
        screen.refresh()
        user_choice = screen.getstr(3).decode('UTF-8')
        if user_choice.lower() == 'p': screen_index = max(0, screen_index-1)
        if user_choice.lower() == 'n': screen_index = min(screen_index+1, max_screen_index)
        #### Exit the loop if user made a valid choice
        if user_choice.lower() == 'q': break
        if is_str_an_int_within_range(user_choice, 1, min(max_choices_per_screen, num_items)): break
    # Don't skip releasing the screen or the terminal will get wonky!
    end_curses_screen(screen)
    if user_choice.lower() == 'q': return None
    # Convert the user's choice to a list index
    list_index = first_list_index + int(user_choice) - 1
    return list_index

def handle_context_arg(kubeconfig):
    """Series of interactive prompts to change the current context: narrow down
    the choices by first choosing a cluster, then a user, and finally the context"""
    #### Prompt for the cluster
    clusters = kubeconfig.get_clusters()
    cluster_index = prompt_user_for_list_choice("cluster", clusters)
    if cluster_index == None: 
        print("Cancelled."); return
    cluster_name = (clusters[cluster_index]['name'])
    #### Prompt for one of the cluster's users
    users = get_users_of_cluster(cluster_name, kubeconfig)
    if len(users) == 0: 
        raise LookupError("Cluster '{}' doesn't have any users defined".format(cluster_name))
    if len(users) == 1:
        user_index = 0  # Only 1 user, so no need to prompt for which user
    else: 
        user_index = prompt_user_for_list_choice("user", users)
        if user_index == None: print("Cancelled."); return
    user_name = users[user_index]['name']
    #### Prompt for a context that has both the selected cluster and user
    contexts = get_matching_contexts(cluster_name, user_name, kubeconfig)
    if len(contexts) == 0: 
        raise LookupError("Cluster '{}' doesn't have any contexts defined".format(cluster_name))
    if len(contexts) == 1:
        context_index = 0  # Only 1 context, so no need to prompt for which context
    else:
        fields_to_print = ['name', 'namespace']  # When listing the contexts, include these fields
        context_index = prompt_user_for_list_choice("context", contexts, fields_to_print)
        if context_index == None: print("Cancelled."); return
    new_context_name = contexts[context_index]['name']
    #### Get user's confirmation, then change the current context
    if new_context_name == kubeconfig.current_context:
        print("The chosen context is already current. No change needed.\n  {}".format(
            kubeconfig.summarize_context(new_context_name, indent_fields=4)))
    else:
        message =  "Change the current context?\n"
        summary =  "  From context: {}\n".format(kubeconfig.current_context)
        summary += "  To " + kubeconfig.summarize_context(new_context_name, indent_fields=5)
        if confirm_in_curses(message + summary + "\n\nConfirm [y/N]: "):
            kubeconfig.use_context(new_context_name)
            print("Successfully changed context\n{}".format(summary))
        else: print("Cancelled.")

def create_name_from_url(cluster_url):
    name = cluster_url.replace("https://", "")
    name = name.replace("http://", "")
    name = name.replace(".", "-")
    return name

def prompt_cluster_details(cluster_url, kubeconfig):
    """Prompt the user for details about the cluster, including how to handle
    any conflicts with existing clusters in the kubeconfig"""
    use_existing_cluster = False
    insecure = None  # Only relevant for new/update, not re-use
    matching_clusters = kubeconfig.search_objects("clusters", {'server': cluster_url})
    if matching_clusters:
        msg = "Kubeconfig already has these cluster(s) with the same URL. Would you like to re-use one?\n"
        list_index = prompt_user_for_list_choice("cluster", matching_clusters, prompt_msg=msg)
        if list_index == None:
            print("Not re-using an existing cluster.")
            use_existing_cluster = False
        else:
            cluster_name = matching_clusters[list_index]['name']
            print("Using existing cluster '{}'".format(cluster_name))
            cluster_data = matching_clusters[list_index]['cluster']
            if "insecure-skip-tls-verify" in cluster_data and cluster_data["insecure-skip-tls-verify"] == True:
                insecure = True
            use_existing_cluster = True
    if not use_existing_cluster:
        suggested_cluster_name = create_name_from_url(cluster_url)
        cluster_name = input("Enter a descriptive name (no spaces) for the cluster [{}]: ".format(suggested_cluster_name))
        if not cluster_name: cluster_name = suggested_cluster_name
        if kubeconfig.get_clusters(cluster_name):
            overwrite = confirm("There is already a cluster called '{}', overwrite it? [y/N]".format(cluster_name))
            if not overwrite: print("Cancelled."); return None, None, None
        while True:
            insecure_resp = input("Skip TLS verification? [y/N]")
            if insecure_resp.lower() == 'y':
                insecure = True
                break
            if insecure_resp.lower() == 'n' or insecure_resp == '':
                insecure = False
                break
    return cluster_name, use_existing_cluster, insecure

def compose_login_summary(cluster_name, use_existing_cluster, user_name, context_name):
    summary = "Login details:\n"
    if use_existing_cluster: cluster_name += " (re-use existing)"
    summary += "  cluster: '{}'\n".format(cluster_name)
    summary += "  user: '{}'\n".format(user_name)
    summary += "  context: '{}'\n".format(context_name)
    summary += "Proceed with kubeconfig changes? [y/N]"
    return summary

def handle_login_arg(kubeconfig):
    """Series of interactive prompts to add a new cluster/user/context and make the
    context the current context. Optionally re-use or update an existing cluster."""
    cluster_url = input("Enter the cluster URL (example https://my.example.com:8443): ")
    cluster_name, use_existing_cluster, insecure = prompt_cluster_details(cluster_url, kubeconfig)
    if not cluster_name: return  # User cancelled the login process
    user_name = input("Enter a descriptive name (no spaces) for the User (example janedoe--mycluster): ")
    # Make sure the user object doesn't already exist
    if kubeconfig.get_users(user_name):
        while True:
            new_user_name = input("User '{}' already exists, please enter a different name: ".format(user_name))
            if new_user_name != user_name and new_user_name != "":
                user_name = new_user_name
                break
    token = input("Enter your token: ")
    server_ok = test_k8s_connectivity(cluster_url, token=token, insecure=insecure)
    if not server_ok: return  # test_k8s_connectivity() will have already displayed the error message
    suggested_context_name = cluster_name + "--" + user_name  # Different separator than OpenShift, no namespace
    context_name = input("Enter a descriptive name (no spaces) for this context [{}]: ".format(suggested_context_name))
    if not context_name: context_name = suggested_context_name
    #### Check for conflicts with existing contexts
    if kubeconfig.get_contexts(context_name):
        if kubeconfig.is_context_openshift(context_name):
            print("There is already an OpenShift context called '{}'. You should use 'oc login' to manage it.".format(context_name))
            return
        overwrite = confirm("There is already a context called '{}', overwrite it? [y/N]".format(context_name))
        if not overwrite: print("Cancelled."); return
    #### Create the cluster (if needed), user, and context
    msg = compose_login_summary(cluster_name, use_existing_cluster, user_name, context_name)
    if confirm(msg):
        if not use_existing_cluster:
            kubeconfig.set_cluster(cluster_name, cluster_url, insecure)
        kubeconfig.set_user(user_name, token=token)
        kubeconfig.set_context(context_name, cluster=cluster_name, user=user_name)
        kubeconfig.use_context(context_name)
    else: print("Cancelled.")

def handle_namespace_arg(ns, kubeconfig):
    current_ctx = kubeconfig.current_context
    assert (current_ctx), \
        "The kubeconfig has no current context. Use --context or --login to set one."
    assert (kubeconfig.is_namespace_valid(ns)), \
        "The specified namespace is not available. Check your connectivity and user permissions."
    #### OpenShift: Find or create a new context that includes the new namespace
    if kubeconfig.is_context_openshift(current_ctx):
        name_parts = current_ctx.split('/')  # OpenShift style: [namespace]/<cluster>/<username>
        new_context_name = "{}/{}/{}".format(ns, name_parts[1], name_parts[2])
        if kubeconfig.exists_in(new_context_name, "contexts"):
            if confirm("Change to existing context '{}'? (Y/[N])".format(new_context_name)):
                kubeconfig.use_context(new_context_name)
                print("Done.")
            else: print("Cancelled.")
        else:  # Specified context doesn't exist, so create it
            # Create a context with the current cluster and user, and the specified namespace
            confirm_msg = \
                "Create new OpenShift-style context '{}' and make current? (Y/[N])".format(new_context_name)
            if confirm(confirm_msg):
                user_name="{}/{}".format(name_parts[2], name_parts[1])  # OpenShift style: <username>/<cluster>
                kubeconfig.set_context(new_context_name, cluster=name_parts[1], namespace=ns, user_name=user)
                kubeconfig.use_context(new_context_name)
                print("Done.")
            else: print("Cancelled.")
    #### Non-OpenShift: simply update the current context with the new namespace
    else:
        confirm_msg = \
            "Update non-OpenShift context '{}' with namespace '{}'? (Y/[N])".format(current_ctx, ns)
        if confirm(confirm_msg):
            kubeconfig.set_context(current_ctx, namespace=ns)
            print("Done.")
        else: print("Cancelled.")

def main():
    args = get_args()
    if args.debug: logging.basicConfig(level='DEBUG')
    kubeconfig = Kubeconfig(args.kubeconfig)
    if args.context: handle_context_arg(kubeconfig)
    if args.login: handle_login_arg(kubeconfig)
    if args.namespace: handle_namespace_arg(args.namespace, kubeconfig)
    # Default action if the main options aren't chosen
    if not (args.context or args.login or args.namespace):
        print("Current " + kubeconfig.summarize_context(kubeconfig.current_context, 2))

if __name__ == "__main__":
    main()