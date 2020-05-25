# kube-ahoy
Kube Ahoy! Easily manage your kubeconfig for a whole fleet of Kubernetes clusters.

### A "plethora" of contexts
I wrote this utility because each time I added a new cluster to my kubeconfig, I found that keeping everything in my kubeconfig straight got a little harder. In particular, I found that OpenShift clusters caused my kubeconfig to practically explode with contexts. Kube-ahoy provides an easy, interactive menu to help you switch contexts by choosing a cluster, user, and namespace.

```
# Change to a different context, via a sweet full-screen menu
./kube-ahoy.py --context

# Get useful details about the current context
./kube-ahoy.py

# See parameter usage details and examples
./kube-ahoy.py --help
```

### Clean namespace switching
To complicate matters further, different CLI tools take different approaches to changing namespaces. In particular, OpenShift's *oc* creates a separate context for each namespace. Kube-ahoy has a namespace switching function that determines whether your current context is for OpenShift or not (based on *oc login*'s naming convention), and updates the namespace accordingly. For non-OpenShift clusters, it simply updates the namespace field of the current context. For OpenShift clusters, it either finds an existing context with the namespace, or creates a new one. In either case, it makes sure that the user can access the namespace before making any changes.

```
./kube-ahoy.py -n my-awesome-namespace
```

I recall other cluster CLI's having similar approaches to OpenShift's. If they're identifieable by their context naming convention, then this feature can be easily extended to include them.

### Interactive login
One thing I like about OpenShift is how *oc login* prompts you for credentials and then updates your kubeconfig for you. I thought it might be cool to have something similar for other Kubernetes clusters. Kube-ahoy provides a friendly, interactive login feature, which also includes some safeguards over raw kubectl to help prevent accidentally breaking exsiting objects in your kubeconfig.  It also verifies your login info/creds before making any changes to your kubeconfig.

```
./kube-ahoy.py --login
```

Caveats
- Does not include an option for client cert auth. 
  - Currently only supports token and basic username/pass authentication.
  - In my experiences, client cert auth has been auto-generated by a cluster CLI or UI, so I didn't think it was a good fit for an interactive login.
  - I might add an option in the future for selectively importing a context from another kubeconfig file. I think this would better address the client cert auth scenarios.
- Does not replace *oc login* for your OpenShift clusters. *oc login* converts your OpenShift username/password into a limited-duration token on the fly, and it enforces its naming convention for new objects.

## Design Considerations
I'll probably end up using this script on multiple systems.  In order to make it easier to manage/distribute, I really wanted it to be self-contained within a single file.  To that end, the following standard libraries and command line tools were used instead of libraries that required a pip install:

- 'json' library instead of the PyYAML library.
- input() function instead of the 'readchar' library.
- curl command instead of the 'requests' library. curl is already required by kubectl.
- kubectl command instead of the 'kubernetes' library.

## So why is it called "kube-ahoy"?
Given Kubernetes' nautical theme, "ahoy!" is the only sensible greeting when boarding a ship... err... Kubernetes cluster.  Also, "kube-ahoy" kinda reminds me of that cereal, "Chips Ahoy," which is all about having cookies for breakfast. And that makes the pirate in me smile.