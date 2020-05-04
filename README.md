# kube-ahoy
Kube Ahoy! Easily manage your kubeconfig for a whole fleet of Kubernetes clusters.

### A "plethora" of contexts
I wrote this utility because each time I added a new cluster to my kubeconfig, I found that keeping everything in my kubeconfig straight got a little harder.  kube-ahoy provides an easy, interactive menu to help you switch contexts by choosing a cluster, user, and namespace.

```
# Get useful details about the current context
./kube-ahoy.py

# Change to a different context, via a sweet full-screen menu
./kube-ahoy.py --context
```

### Clean namespace switching
To complicate matters further, different CLI tools take different approaches to changing namespaces. In particular, OpenShift's *oc* creates a separate context for each namespace. kube-ahoy has a namespace switching funtion that determines whether your current context is for OpenShift or not (based on *oc login*'s naming convention), and updates the namespace appropriately.  For OpenShift clusters, it either finds an existing context with the namespace, or creates a new one. For non-OpenShift clusters, it simply updates the namespace field of the current context. In either case, it makes sure that the user can access the namespace before making any changes.

```
./kube-ahoy.py -n my-awesome-namespace
```

I recall other cluster CLI's like *aws eks* having similar approaches to OpenShift's. If they're identifieable by their context naming convention, then this feature can be easily extended to include them.

### Interactive login
One thing I like about OpenShift is how *oc login* prompts you for credentials and then updates your kubeconfig accordingly. I thought it might be cool to have something similar for other Kubernetes clusters. kube-ahoy provides a login feature, which includes some safeguards over raw kubectl to help prevent accidentally breaking exsiting objects in your kubeconfig.

```
./kube-ahoy.py --login
```

Caveats
- It only works for token auth at the moment.
  - I considered adding client cert auth, but I've only encounted 2 client auth scenarios, and neither seemed like a fit for interactive logins:
    - Cluster UI's that provide you a kubeconfig file with which to connect
    - Cluster CLI's that update your kubeconfig directly
  - To address these use cases, I might add an option in the future for selectively importing a context from another kubeconfig file.
- Keep using *oc login* for your OpenShift clusters. It enforces its own naming convention, and it converts your OpenShift username/password into a token on the fly.

## Design Considerations
I'll probably end up using this script on multiple systems.  In order to make it easier to manage/distribute, I really wanted it to be self-contained within a single file.  To that end, the following standard libraries and command line tools were used instead of libraries that required a pip install:

- 'json' library instead of the PyYAML library
- 'urllib' library instead of the 'requests' library
- input() function instead of the 'readchar' library
- kubectl command instead of the 'kubernetes' library

## Why "kube-ahoy"?
Given Kubernetes' nautical theme, "ahoy" is the only sensible greeting when boarding a ship... err... Kubernetes cluster.  Also, "kube-ahoy" kinda reminds me of that cereal, Chips Ahoy! which is all about having cookies for breakfast. And that makes the pirate in me smile.