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
- input() function instead of the 'readchar' library
- kubectl command instead of the 'kubernetes' library
- curl command instead of the 'requests' library (also, kubectl uses curl, so it makes a more 
                                                  apples-to-apples test than requests or urllib)
"""

import os
import math
import logging
import argparse
import curses    # Control the terminal screen; not in Windows
import json
import subprocess
import getpass
import base64
import tempfile

class Kubeconfig(object):
    """Manages the local kubeconfig and its contexts. Requires kubectl to be installed."""
    kubeconfig_file = None  # optional, alternative kubeconfig file to use
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
        if self.kubeconfig_file:
            if not os.path.exists(self.kubeconfig_file):
                raise FileNotFoundError("Cannot find the specified kubeconfig file '{}'".format(self.kubeconfig_file))
            cmd += " --kubeconfig {}".format(self.kubeconfig_file)
        output, returncode = self.__run_cmd(cmd)
        self.kubeconfig_data = json.loads(output)
        self.logger.debug( "Retrieved: {} context(s), {} cluster(s), {} user(s)".format (
            self.__safe_len(self.kubeconfig_data['contexts']), 
            self.__safe_len(self.kubeconfig_data['clusters']), 
            self.__safe_len(self.kubeconfig_data['users'])
        ))

    def __run_cmd(self, cmd, args_with_spaces=[], input=None, fail_on_non_zero=True, no_log_cmd=False):
        """Run a command in the OS. Any command args that contain spaces should be 
        passed separately in the args_with_spaces list param (don't include quotes)"""
        result = subprocess.run(cmd.split() + args_with_spaces, 
            input=input, 
            stdout=subprocess.PIPE,   # send stderr to stdout
            stderr=subprocess.STDOUT)
        output = result.stdout.decode('utf-8').rstrip()
        returncode = result.returncode
        for arg in args_with_spaces:
            cmd += " " + arg
        if no_log_cmd: cmd = "[REDACTED]"
        summary = "\n  Command: {}".format(cmd) + \
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
        if not self.kubeconfig_data[type]: return None
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
        if not self.kubeconfig_data[obj_type]: return False
        for object in self.kubeconfig_data[obj_type]:
            if object['name'] == obj_name: return True
        return False

    def use_context(self, context_name):
        """Make the specified context the current context"""
        cmd = "kubectl config use-context " + context_name
        if self.kubeconfig_file: cmd += " --kubeconfig=" + self.kubeconfig_file
        self.__run_cmd(cmd)
        self.current_context = context_name

    def set_context(self, context, cluster=None, user=None, namespace=None):
        """Update or create the specified context with the specified fields"""
        assert (cluster or user or namespace), \
            "set_context() requires at least one of: cluster, user, namespace"
        cmd = "kubectl config set-context " + context
        if cluster: cmd += " --cluster=" + cluster
        if user: cmd += " --user=" + user
        if namespace: cmd += " --namespace=" + namespace
        if self.kubeconfig_file: cmd += " --kubeconfig=" + self.kubeconfig_file
        self.__run_cmd(cmd)

    def set_cluster(self, cluster_name, cluster_url, ca_cert=None, insecure=False):
        """Update or create the specified cluster with the specified fields"""
        cmd = "kubectl config set-cluster " + cluster_name
        if cluster_url: cmd += " --server=" + cluster_url
        if self.kubeconfig_file: cmd += " --kubeconfig=" + self.kubeconfig_file
        if ca_cert:
            # Create a secure temp file for the CA cert, and make sure it gets deleted
            fd, path = tempfile.mkstemp(text=True)
            cmd += " --certificate-authority={} --embed-certs=true".format(path)
            try:
                with os.fdopen(fd, 'w') as tmp:
                    tmp.write(ca_cert)
                    tmp.close()
                self.__run_cmd(cmd)
            finally:
                os.remove(path)
        else:
            if insecure: cmd += " --insecure-skip-tls-verify=true"
            self.__run_cmd(cmd)

    def set_user(self, user_name, token=None, username=None, password=None):
        """Update or create the specified user with the specified fields"""
        assert (token or (username and password)), \
            "set_user() requires at least one of: token, username+password"
        cmd = "kubectl config set-credentials " + user_name
        if self.kubeconfig_file: cmd += " --kubeconfig=" + self.kubeconfig_file
        if token: 
            cmd += " --token=" + token
            self.__run_cmd(cmd)
        else:
            cmd += " --username={} --password={}".format(username, password)
            self.__run_cmd(cmd, no_log_cmd=True)

    def test_auth(self, cluster_url, token=None, username=None, password=None, ca_cert=None, insecure=False):
        """Test connecting to the cluster URL (format: 'https://my.cluster.com:6443') 
        via the provided auth method."""
        assert (token or (username and password)), \
            "test_auth() requires at least one of: token, username+password"
        timeout_secs = 10
        cmd = "curl -v -XGET {}/api --connect-timeout {} ".format(cluster_url, timeout_secs)
        args_with_spaces = []  # extra cmd args that have spaces (don't include quotes)
        if token:
            args_with_spaces.append('-HAuthorization: Bearer {}'.format(token))
            sanitized_cmd = cmd +  ' -H "Authorization: Bearer {}"'.format("[REDACTED]")
        else: 
            #### base64 encode the username:password for Basic auth
            creds_text = "{}:{}".format(username, password)
            creds_bytes = creds_text.encode('ascii')
            base64_bytes = base64.b64encode(creds_bytes)
            base64_text = base64_bytes.decode('ascii')
            args_with_spaces.append('-HAuthorization: Basic {}'.format(base64_text))
            sanitized_cmd = cmd +  ' -H "Authorization: Basic {}"'.format("[REDACTED]")
        if ca_cert:
            # Create a secure temp file for the CA cert, and make sure it gets deleted when done
            fd, path = tempfile.mkstemp(text=True)
            cmd += " --cacert " + path
            sanitized_cmd += " --cacert " + path
            try:
                with os.fdopen(fd, 'w') as tmp:
                    tmp.write(ca_cert)
                    tmp.close()  # Save the file
                self.logger.debug("Testing authentication:\n" + sanitized_cmd)
                output, returncode = self.__run_cmd(cmd, args_with_spaces=args_with_spaces, fail_on_non_zero=False, no_log_cmd=True)
            finally:
                os.remove(path) # Remove the file
        else:
            if insecure: 
                cmd += " -k"
                sanitized_cmd += " -k"
            self.logger.debug("Testing authentication:\n" + sanitized_cmd)
            output, returncode = self.__run_cmd(cmd, args_with_spaces=args_with_spaces, fail_on_non_zero=False, no_log_cmd=True)
        if returncode == 0: return True
        else: return False

    def is_namespace_valid(self, namespace):
        """Check whether the namespace is available in the current context"""
        cmd = "kubectl get ns {}".format(namespace)
        if self.kubeconfig_file: cmd += " --kubeconfig=" + self.kubeconfig_file
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
            "incorrect obj_type '{}', must be one of: contexts, clusters, users".format(obj_type)
        if not self.kubeconfig_data[obj_type]: return []
        search_items = []
        # Loop through all objects
        for object in self.kubeconfig_data[obj_type]:
            singular_type = obj_type.rstrip('s')
            match = True  # Tracks whether this object matches ALL the search fields
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

    def get_users_of_cluster(self, cluster_name):
        """Return a list of user dicts that are in the same contexts as the specified cluster"""
        #### Get all the contexts of the specified cluster
        fields_to_match = {'cluster': cluster_name}
        contexts = self.search_objects('contexts', fields_to_match)
        #### Read the user (name) from each context, and look up the user object
        users = []
        for ctx in contexts:
            user_name = ctx['context']['user']
            user_obj = self.get_users(user_name)
            if user_obj not in users:
                users.append(user_obj)
        return users

    def summarize_context(self, context_name, indent_fields=2):
        """Render the context obj in a string that looks nice, for printing on-screen"""
        if not self.kubeconfig_data['contexts']:
            summary = "context: <none>"
            return summary
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
        formatter_class=argparse.RawTextHelpFormatter)  # Preserve newlines
    parser.add_argument('-d','--debug', action='store_true', help="enable debug-level logging")
    parser.add_argument('--kubeconfig', metavar='<filepath>', action='store', help=kubeconfig_help)
    pick_one = parser.add_mutually_exclusive_group(required=False)
    pick_one.add_argument('-l','--login', action='store_true', help=login_help)
    pick_one.add_argument('-c','--context', action='store_true', help=ctx_help)
    pick_one.add_argument('-n','--namespace', metavar='<name>', action='store', help=ns_help)
    return parser.parse_args()

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

def get_choice(msg, choices):
    """The choices param must be a list of strings. Prints the message, and then
    waits for the user to enter one of the strings in choices (case-insensitive).
    Returns the user's validated entry, in lower case."""
    valid_choice_entered = False
    while not valid_choice_entered:
        response = input(msg)
        for potential_choice in choices:
            if response.lower() == potential_choice.lower():
                valid_choice_entered = True
                break
    return response.lower()

def input_multiline(msg, end_line):
    """Prints message and allows the user to enter a multiline string. Stops
    prompting for lines when the user enters a line matching the end_line
    param (case-insensitive). If end_line is '\n' then it stops prompting
    when the user enters a blank line (press ENTER twice in a row)."""
    print(msg)
    all_lines = ""
    first_line = True
    while True:
        line = input()
        if line.lower() == end_line.lower(): break
        if end_line == '\n' and line == "": break
        # Add a preceding newline char if this is not the first line. Using
        # a bool is better than checking (all_lines==True), because there is
        # no confusion when the first line is blank.
        if not first_line: all_lines += '\n'
        first_line = False
        all_lines += line
    return all_lines

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
        menu_line = "({})".format(str(choice_num)).ljust(5, ' ')  # Format choice number
        for field in fields_to_print:
            menu_line += "{}: '{}'  ".format(field, item[field])
        menu += menu_line + "\n"
        choice_num += 1
    return menu

def prompt_user_for_list_choice(list_item_singular, list, fields_to_print=['name'], prompt_msg = "", exit_prompt="Cancel"):
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
        if screen_index < max_screen_index: nav_choices += "(N)ext screen, "
        if screen_index > 0: nav_choices += "(P)revious screen, "
        nav_choices += "(X)  {}\n\nMake your choice and press ENTER: ".format(exit_prompt)
        screen.addstr(nav_choices)
        #### Render screen and get user's choice
        screen.refresh()
        user_choice = screen.getstr(3).decode('UTF-8')
        if user_choice.lower() == 'p': screen_index = max(0, screen_index-1)
        if user_choice.lower() == 'n': screen_index = min(screen_index+1, max_screen_index)
        #### Exit the loop if user made a valid choice
        if user_choice.lower() == 'x': break
        if is_str_an_int_within_range(user_choice, 1, min(max_choices_per_screen, num_items)): break
    # Don't skip releasing the screen or the terminal will get wonky!
    end_curses_screen(screen)
    if user_choice.lower() == 'x': return None
    # Convert the user's choice to a list index
    list_index = first_list_index + int(user_choice) - 1
    return list_index

def handle_context_arg(kubeconfig):
    """Handle the --context command line arg. Presents a series of interactive prompts to change 
    the current context: narrow down the choices by first choosing a cluster, then a user, and 
    finally the context."""
    #### Prompt for the cluster
    clusters = kubeconfig.get_clusters()
    if not clusters:
        print("Kubeconfig does not contain any clusters.")
        return
    cluster_index = prompt_user_for_list_choice("cluster", clusters)
    if cluster_index == None: 
        print("Cancelled."); return
    cluster_name = (clusters[cluster_index]['name'])
    #### Prompt for one of the cluster's users
    users = kubeconfig.get_users_of_cluster(cluster_name)
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
        if confirm_in_curses(message + summary + "\n\nConfirm y/[N]: "):
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
    ca_cert = None
    insecure = None  # Only relevant for new/update, not reuse
    matching_clusters = kubeconfig.search_objects("clusters", {'server': cluster_url})
    if matching_clusters:
        msg = "Kubeconfig already has these cluster(s) with the same URL. Would you like to reuse one?\n"
        list_index = prompt_user_for_list_choice("cluster", matching_clusters, prompt_msg=msg, exit_prompt="X No thanks, I'll create or overwrite one")
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
            overwrite = confirm("There is already a cluster called '{}', overwrite it? y/[N]: ".format(cluster_name))
            if not overwrite: print("Cancelled."); return None, None, None, None
        if confirm("Enter a CA cert for TLS verification? This is for untrusted CA's. y/[N]: "):
            insecure = False
            while True:
                ca_cert = input_multiline("Paste your CA cert. When done, enter a blank line (press ENTER twice):", '\n')
                bad_cert = (ca_cert.find("BEGIN CERTIFICATE") == -1) or (ca_cert.find("END CERTIFICATE") == -1)
                if not bad_cert: break
                msg = 'Not a valid PEM cert. It should start/end with "-----BEGIN CERTIFICATE-----" and "-----END CERTIFICATE-----".\nTry again? [Y]/n'
                if not confirm(msg, enter=True):
                    ca_cert = None
                    break
        if not ca_cert:
            insecure = confirm("Skip TLS verification (insecure)? For testing with self-signed certs, or untrusted CA's. y/[N]: ")
    return cluster_name, use_existing_cluster, ca_cert, insecure

def compose_login_summary(cluster_name, use_existing_cluster, user_name, context_name):
    summary = "Login details:\n"
    if use_existing_cluster: cluster_name += " (reuse existing)"
    summary += "  cluster: '{}'\n".format(cluster_name)
    summary += "  user: '{}'\n".format(user_name)
    summary += "  context: '{}'\n".format(context_name)
    summary += "Proceed with kubeconfig changes? y/[N]: "
    return summary

def prompt_user_details(cluster_name, kubeconfig):
    """Prompt for details about the user object. The cluster nameis used
    to check for conflicts with existing users"""
    token = None
    username = None
    password = None
    use_existing_user = False
    user_name = input("Enter a descriptive name (no spaces) for the User (example janedoe--mycluster): ")
    # Check the specified user_name for conflicts, and re-prompt the user if needed
    while True:
        #### Make sure the user object doesn't already exist
        if not kubeconfig.get_users(user_name): break
        #### If it exists, see if the existing object is for the same cluster, and could therefore be reused or overwritten
        user_objects = kubeconfig.get_users_of_cluster(cluster_name)
        user_object_names = [ user['name'] for user in user_objects ]
        if user_name in user_object_names:
            msg = "User '{}' of cluster '{}' already exists. Do you want to (r)euse, (o)verwrite, or (c)ancel? ".format(user_name, cluster_name)
            choice = get_choice(msg, ['r', 'o', 'c'])
            if choice == 'r': 
                use_existing_user = True; 
                break
            if choice == 'o':
                # Overwriting an existing user is technically the same as creating a new one
                break
            if choice == 'c':
                print("Cancelled.")
                return None, None, None, None, None
        else:
            user_name = input("User '{}' already exists for a different cluster. Please enter a different name: ".format(user_name))
    if not use_existing_user:
        auth_type = get_choice("Which authentication method? [b]asic username+password, or [t]oken: ", ['b','t'])
        if auth_type == 'b':
            username = input("Enter username: ")
            password = getpass("Enter password: ")
        if auth_type == 't':
            token = input("Enter token: ")
    return user_name, use_existing_user, token, username, password

def handle_login_arg(kubeconfig):
    """Handle the --login command line arg. Presents a series of interactive prompts to add a new 
    cluster/user/context, and make the context the current context. Optionally reuse or update existing 
    cluster and/or user objects."""
    cluster_url = input("Enter the cluster URL (example https://my.example.com:8443): ")
    cluster_name, use_existing_cluster, ca_cert, insecure = prompt_cluster_details(cluster_url, kubeconfig)
    if not cluster_name: return  # User cancelled the login process
    user_name, use_existing_user, token, username, password = prompt_user_details(cluster_name, kubeconfig)
    if not user_name: return  # User cancelled the login process
    if not use_existing_user:
        server_ok = kubeconfig.test_auth(cluster_url, token, username, password, ca_cert, insecure)
        if not server_ok: 
            print("Unable to connect/authenticate to the cluster. Use --debug for details.")
            return
    if use_existing_cluster and use_existing_user:
        print("Reusing both an existing cluster and an existing user - nothing to do. Login cancelled.")
        return
    suggested_context_name = cluster_name + "--" + user_name  # Different separator than OpenShift, no namespace
    context_name = input("Enter a descriptive name (no spaces) for this context [{}]: ".format(suggested_context_name))
    if not context_name: context_name = suggested_context_name
    #### Check for conflicts with existing contexts
    if kubeconfig.get_contexts(context_name):
        if kubeconfig.is_context_openshift(context_name):
            print("There is already an OpenShift context called '{}'. You should use 'oc login' to manage it.".format(context_name))
            return
        overwrite = confirm("There is already a context called '{}', overwrite it? y/[N]: ".format(context_name))
        if not overwrite: print("Cancelled."); return
    #### Create the cluster (if needed), the user, and the context
    msg = compose_login_summary(cluster_name, use_existing_cluster, user_name, context_name)
    if confirm(msg):
        if not use_existing_cluster:
            kubeconfig.set_cluster(cluster_name, cluster_url, ca_cert, insecure)
        if not use_existing_user:
            kubeconfig.set_user(user_name, username=username, password=password, token=token)
        kubeconfig.set_context(context_name, cluster=cluster_name, user=user_name)
        kubeconfig.use_context(context_name)
    else: print("Cancelled.")

def handle_namespace_arg(ns, kubeconfig):
    """Handle the --namespace command line arg."""
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
            if confirm("Change to existing context '{}'? [y/N]: ".format(new_context_name)):
                kubeconfig.use_context(new_context_name)
                print("Done.")
            else: print("Cancelled.")
        else:  # Specified context doesn't exist, so create it
            # Create a context with the current cluster and user, and the specified namespace
            confirm_msg = \
                "Create new OpenShift-style context '{}' and make current? y/[N]: ".format(new_context_name)
            if confirm(confirm_msg):
                user_name="{}/{}".format(name_parts[2], name_parts[1])  # OpenShift style: <username>/<cluster>
                kubeconfig.set_context(new_context_name, cluster=name_parts[1], namespace=ns, user_name=user)
                kubeconfig.use_context(new_context_name)
                print("Done.")
            else: print("Cancelled.")
    #### Non-OpenShift: simply update the current context with the new namespace
    else:
        confirm_msg = \
            "Update non-OpenShift context '{}' with namespace '{}'? y/[N]: ".format(current_ctx, ns)
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