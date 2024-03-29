# kube-ahoy
Kube Ahoy! Easily manage your kubeconfig for a whole fleet of Kubernetes clusters.

### A plethora of contexts
I wrote this utility because each time I added a new cluster to my kubeconfig, I found that keeping everything in my kubeconfig straight got a little harder. In particular, I found that OpenShift clusters caused my kubeconfig to practically explode with contexts. Kube-ahoy provides an easy, interactive menu to help you switch contexts by choosing a cluster, user, and namespace.

```bash
# Change to a different context, via a sweet full-screen menu
./kube-ahoy.py --context

# Get useful details about the current context
./kube-ahoy.py

# See parameter usage details and examples
./kube-ahoy.py --help
```

### Clean namespace switching
To complicate matters further, different CLI tools take different approaches to changing namespaces. In particular, OpenShift's `oc` creates a separate context for each namespace. Kube-ahoy has a namespace switching function that determines whether your current context is for OpenShift or not (based on `oc login`'s naming convention), and updates the namespace accordingly. For non-OpenShift clusters, it simply updates the namespace field of the current context. For OpenShift clusters, it either finds an existing context with the namespace, or creates a new one. In either case, it makes sure that the user can access the namespace before making any changes.

```bash
./kube-ahoy.py -n my-awesome-namespace
```

I seem to recall other cluster CLI's having similar approaches to OpenShift's. If they're identifieable by their context naming convention, then this feature can be easily extended to include them.

### Interactive login
One thing I like about OpenShift is how `oc login` prompts you for credentials and then updates your kubeconfig for you. I thought it might be cool to have something similar for other Kubernetes clusters. Kube-ahoy provides a friendly, interactive login feature, which also includes some safeguards over raw kubectl to help prevent accidentally breaking exsiting objects in your kubeconfig.  It also verifies your login info/creds before making any changes to your kubeconfig.

```bash
./kube-ahoy.py --login
```

Caveats
- Does not include an option for client cert auth.
  - Client cert auth is usually best handled by SSO/Oauth and their related kubectl plugins, like kubelogin.
  - Currently only supports token and basic username/pass authentication.
- Does not replace `oc login` for connecting to OpenShift clusters.
  - `oc login` converts your OpenShift username/password into a limited-duration token on the fly.
  - You will still need to use `oc login` to re-authenticate to OpenShift every so often, which updates this token in your kubeconfig.

## Design Considerations
I use this script on multiple systems.  In order to make it easier to manage/distribute, I really wanted it to be self-contained within a single file.  This allows me to easily scp it or copy+paste it into a text editor over ssh. To that end, the following standard libraries and command line tools were used instead of libraries that required a pip install:

- `json` library instead of the `PyYAML` library.
- `input()` function instead of the `readchar` library.
- `kubectl` command instead of the `kubernetes` library.
- `curl` command instead of the `requests` library. `curl` is already required by `kubectl`.

## So why is it called "kube-ahoy"?
Given Kubernetes' nautical theme, "ahoy!" is the only sensible greeting when boarding a ship... err... Kubernetes cluster.
