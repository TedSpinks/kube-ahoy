# kube-ahoy
Kube Ahoy! Easily manage your kubeconfig for a whole fleet of Kubernetes clusters.

### A "plethora" of contexts
I wrote this utility because each time I added a new cluster to my kubeconfig, I found that remembering all the context names got a little harder.  kube-ahoy provides an easy, interactive menu to choose a context based on cluster, user, and namespace.

```
# Get useful details about the current context
./kube-ahoy.py

# Change to a different context, via a sweet menu
./kube-ahoy.py --context
```

### Change namespaces cleanly
To further complicate matters, different CLI tools take different approaches to changing namespaces. In particular, OpenShift likes to create a separate context for each namespace. kube-ahoy has a nice namespace switching funtion that determines whether your current context is for OpenShift or not (based on *oc login*'s naming convention), and updates the namespace appropriately.  For OpenShift clusters, it either finds an existing context with the namespace, or creates a new one. For non-OpenShift clusters, is simply updates the namespace field of the current context. In either case, it makes sure that the user can access the namespace before switching to it.

```
./kube-ahoy.py -n my-awesome-namespace
```

Side note: I recall other cluster CLI's having similar approaches to OpenShift. If they're identifieable by their context naming convention, then this feature can be easily extended to include them as well.

### Interactive login
One thing I've really like about OpenShift is how "oc login" prompts you for credentials and then update your kubeconfig accordingly. Who wants to remember all those "kubectl config" commands??  kube-ahoy has a similar login feature that does the same thing for non-OpenShift clusters. It also has some safeguards over raw kubectl to help prevent accidentally overwriting/breaking exsiting objects in your kubeconfig.

```
./kube-ahoy.py --login
```

Caveats
- It only works for token auth at the moment.  
  - I considered adding client cert auth, but I've only encounted 2 scenarios, and neither seems like a fit for interactive logins:
    1. Cluster UI's that provide you a kubeconfig file with which to connect
    2. Cluster CLI's that update your kubeconfig directly
  - To address these use cases, I might add an option in the future for selectively importing a context from another kubeconfig file.
- Keep using "oc login" for your OpenShift clusters. It enforces its own naming convention, and it converts your OpenShift username/password into a token on the fly

## Design Considerations
In order to make this script easier to manage as new versions come out and/or you add it to various systems, I really wanted it to be self-contained within a single file.  To that end, the following standard libraries and command line tools were used instead of libraries that required a pip install:

- 'json' library instead of the PyYAML library
- 'urllib' library instead of the 'requests' library
- input() function instead of the 'readchar' library
- kubectl command instead of the 'kubernetes' library

## Why kube-ahoy?
Given Kubernetes' nautical theme, "ahoy" seemed the only sensible greeting for boarding a ship... err... Kubernetes cluster.  Kube-ahoy also kinda reminds me of that cereal, Chips Ahoy! which is all about having cookies for breakfast. And that makes the pirate in me happy. Yo ho ho!