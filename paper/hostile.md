# Using Kubernetes in Hostile Networks

## Background

We (Dark3, Inc. DBA Dark Cubed) deploy network security appliances into
environments where we do not maintain full physical control of the
appliances once they are deployed. Each appliance is a Kubernetes node,
meaning it runs the `kubelet` service and therefore has an
authentication token locally present for communicating with the
Kubernetes Master API server.

Given we have no control over physical access to these appliances, it is
pretty easy for someone to boot into the appliance in *single-user mode*
and gain access to the authentication token. Because of this, we need a
way to limit the impact of a bad actor gaining access to an
authentication token present on an appliance.

## Approach

Our approach to limiting the impact of a bad actor gaining access to an
appliance's authentication token is to sandbox each Dark Cubed customer
in their own namespace and limit the scope of a customer's appliance
token (the `default` service account token for the customer's namespace)
to the bare minimum necessary to run pods in that namespace using
Kubernetes rule-based access control (RBAC) resources.

### Testing

In order to determine the minimum level of access the `kubelet` needs to
support a Dark Cubed customer appliance node, we deployed a very simple
Kuberentes test cluster, consisting of a single Kubernetes master,
running both the Kubernetes applications and Etcd, and a single node
representing a Dark Cubed appliance.  The API server running on the
master and the `kubelet` running on the node were configured with
verbose logging (`--v=8`) so we could see what full request paths and
HTTP status. The cloud-config files used for the master and node are
shown below.

### Vagrantfile

```
Vagrant.configure("2") do |config|
  config.ssh.insert_key = false

  config.vm.box     = 'coreos-stable'
  config.vm.box_url = 'http://stable.release.core-os.net/amd64-usr/current/coreos_production_vagrant.json'

  config.vm.provider :virtualbox do |v|
    # On VirtualBox, we don't have guest additions or a functional vboxsf
    # in CoreOS, so tell Vagrant that so it can be smarter.
    v.check_guest_additions = false
    v.functional_vboxsf     = false
  end

  # plugin conflict
  if Vagrant.has_plugin?("vagrant-vbguest") then
    config.vbguest.auto_update = false
  end

  config.vm.provider :virtualbox do |vb|
    vb.cpus = 1
    vb.gui  = false
  end

  config.vm.define 'master' do |box|
    box.vm.hostname = 'master'

    box.vm.provider :virtualbox do |vb|
      vb.memory = 512
    end

    box.vm.network :private_network, ip: '172.17.4.10'
    box.vm.network :forwarded_port,  guest: 6443, host: 6443

    box.vm.provision :file,  :source      => './master.yml',
                             :destination => '/tmp/vagrantfile-user-data'
    box.vm.provision :shell, :inline      => 'mv /tmp/vagrantfile-user-data /var/lib/coreos-vagrant/',
                             :privileged  => true
  end

  config.vm.define 'node' do |box|
    box.vm.hostname = 'node'

    box.vm.provider :virtualbox do |vb|
      vb.memory = 512
    end

    box.vm.network :private_network, ip: '172.17.4.100'

    box.vm.provision :file,  :source      => './node.yml',
                             :destination => '/tmp/vagrantfile-user-data'
    box.vm.provision :shell, :inline      => 'mv /tmp/vagrantfile-user-data /var/lib/coreos-vagrant/',
                             :privileged  => true
  end
end
```

### Kubernetes Master cloud-config (master.yml)

```
#cloud-config
---
write_files:
  - path: /etc/hosts
    permissions: '0644'
    content: |
      127.0.0.1 localhost master
  - path: /opt/bin/wupiao
    permissions: '0755'
    content: |
      #!/bin/bash
      # [w]ait [u]ntil [p]ort [i]s [a]ctually [o]pen
      [ -n "$1" ] && \
        until /usr/bin/curl -o /dev/null -sf ${1}; do \
        sleep 1 && echo .; done;
      exit $?
  - path: /srv/k8s/service-accounts.key
    permissions: '0600'
    content: |
      -----BEGIN RSA PRIVATE KEY-----
      MIIEowIBAAKCAQEA38CNwKrLe3DFGoZZnGVATve9Og7qFmZg2NTTFO9tVePRIxXA
      wD4FKMT6yKCFKZVltrHrfwVxSEAPJB7y76l/1VZOaaVU4aeyGHXzSvrNSGHWMevO
      0GlpAAAzJVqvf3LuNoTROViLQNYu1igwwFCTTdL0kLEdkZhFVM0rJt2IGeiQM/5P
      z0ffq/AIYOO3bZWLOyFueIbid4LlcqUeN6AfRuXIfkgq2UnFnfdxVERA4nsTiEED
      S+Urs1Zn0Rl9RWW5+/yDOIWErV9Q12VlDQiEgOsBV4dhUkU048F4OfSzMOE526Mr
      l3EAt43xE0ALBDFNPiAjCNcXsPko4WhiNZQhiwIDAQABAoIBABQw8hnCz93xzTeZ
      jBia4nS90muc0O74iiDHA81N1dX8WvEJk31Fm32UWPUl1x5rhuQ3pgKuYQyeCz+9
      MzsBVrHPuf+6lbBPS7j9W9kWTNQNUCDtIJqaCImhevwR9OhRXMG6to6wONC/Azb8
      JXoVS1Wohb1Q3lQ3I3qFkTFOqGt979r91bzqZFWr7Dk7McqPnWygmA3q+NwLU9ix
      TlR22XYf+teSj2jD4joFhj1lUxi3dUhSCUf81Ytu/Mtb0CnJUVt6abcHJ0jQJZ1G
      hrXhL1ZAcXDjCc1ArDe1foptk46+2kDfr2Xm7roily5ua37uRMigxs7/y6cMuCak
      ZmIvkOECgYEA+Nz1Fer0IV7JKwK9JDiEBTgIk9vob5s2owuyfZN7PEnEUPNubw2z
      wdf68DLWr8CBC5v+xPPmKLklLCtsuzMgHUpU1Z+fT//PSV/9J0j5whUfmj9av7/8
      hpC368dD/RCAcAcodCgN4tnLaj/P9yl+GyS/M+lBUE0VhLuHIOb3l0MCgYEA5is+
      LZDdK0urPcLywmadV2y3g9eePetwtjzSoylq14TRFY9Kq6KUliyslcgwVm8A9PkD
      wRHds2dtC8Gy1seq2ru1Ic3YVyLPCWVkx2a8M5kVFzclrOZp3KADppjHIoDj/d96
      GUgnnOk3msfEfZbsLIUCa136nBEFhr2Iu1n0dBkCgYEA09y/5Y3lkjcwiaZGQXy/
      n/XJD5+KbOE1jW7a4J9arcObFtN286I1o1PstOqC7JK1CZ4fMar2CTs9kzHQ2jm3
      IFh0inze0utTnALU8Mnmnrz+74D6D/4wzJqNiXNVxS50OWtOnDyxPavuyaBTuvYe
      /pq1EEuGqAdHx30il/cpVyMCgYAL3DSTAoDzBy4mu5HoxILdC2QVbhngVO505YNx
      FuRDgLuJYd3WJEWFy32FJlCfU474EJDJ9RK4eN7cmTmO6bD7HmsB9+pq6wdCE7By
      ue9+tSeqD5RoaWMRFEm73ul79KpK3aYcAWTRKA9OcXbFhe5biOsL/0a3ngTr4X5X
      MRZwmQKBgGsK3di9wz+e5N6xOQqEsEIIOUwnc9PP0421OfjRhtHiUMd5M+RdemnX
      7bEcpZGG2fMbUefw8rBUkr9bKm/vs4hfqP5G3Or8bDOcA7jQdmKTtH5pypcJLJSr
      RoS8VGgtNFt+t/za5Oo6oTluKXuAJy1QXCtJsEjRiR6GQd9Figdb
      -----END RSA PRIVATE KEY-----
  - path: /srv/k8s/auth-tokens.csv
    permissions: '0600'
    content: |
      aithung5kohgheiP7oosheej1uSo4Ifeejoj,foobar,foobar-00
  - path: /etc/kubernetes/manifests/kube-apiserver.yaml
    permissions: '0600'
    content: |
      apiVersion: v1
      kind: Pod
      metadata:
        name: kube-apiserver
        namespace: kube-system
      spec:
        hostNetwork: true
        containers:
        - name: kube-apiserver
          image: quay.io/coreos/hyperkube:v1.5.6_coreos.0
          command:
          - /hyperkube
          - apiserver
          - --advertise-address=$private_ipv4
          - --etcd-servers=http://127.0.0.1:4001
          - --service-cluster-ip-range=10.101.0.0/16
          - --allow-privileged=true
          - --admission-control=NamespaceLifecycle,NamespaceExists,LimitRanger,SecurityContextDeny,ServiceAccount,ResourceQuota
          - --token-auth-file=/etc/k8s/auth-tokens.csv
          - --service-account-lookup=true
          - --service-account-key-file=/etc/k8s/service-accounts.key
          - --runtime-config=rbac.authorization.k8s.io/v1alpha1=true
          - --authorization-mode=RBAC
          - --authorization-rbac-super-user=foobar
          - --v=8
          ports:
          - name: local
            hostPort: 8080
            containerPort: 8080
          - name: secure
            hostPort: 6443
            containerPort: 6443
          volumeMounts:
          - name: ssl-certs-host
            mountPath: /etc/ssl/certs
            readOnly: true
          - name: k8s-configs
            mountPath: /etc/k8s
            readOnly: true
        volumes:
        - name: ssl-certs-host
          hostPath:
            path: /usr/share/ca-certificates
        - name: k8s-configs
          hostPath:
            path: /srv/k8s
  - path: /etc/kubernetes/manifests/kube-scheduler.yaml
    permissions: '0600'
    content: |
      apiVersion: v1
      kind: Pod
      metadata:
        name: kube-scheduler
        namespace: kube-system
      spec:
        hostNetwork: true
        containers:
        - name: kube-scheduler
          image: quay.io/coreos/hyperkube:v1.5.6_coreos.0
          command:
          - /hyperkube
          - scheduler
          - --master=http://127.0.0.1:8080
          - --leader-elect=true
          livenessProbe:
            httpGet:
              host: 127.0.0.1
              path: /healthz
              port: 10251
            initialDelaySeconds: 15
            timeoutSeconds: 1
  - path: /etc/kubernetes/manifests/kube-controller-manager.yaml
    permissions: '0600'
    content: |
      apiVersion: v1
      kind: Pod
      metadata:
        name: kube-controller-manager
        namespace: kube-system
      spec:
        hostNetwork: true
        containers:
        - name: kube-controller-manager
          image: quay.io/coreos/hyperkube:v1.5.6_coreos.0
          command:
          - /hyperkube
          - controller-manager
          - --master=http://127.0.0.1:8080
          - --leader-elect=true
          - --service-account-private-key-file=/etc/k8s/service-accounts.key
          livenessProbe:
            httpGet:
              host: 127.0.0.1
              path: /healthz
              port: 10252
            initialDelaySeconds: 15
            timeoutSeconds: 1
          volumeMounts:
          - name: ssl-certs-host
            mountPath: /etc/ssl/certs
            readOnly: true
          - name: k8s-config
            mountPath: /etc/k8s
            readOnly: true
        volumes:
        - name: ssl-certs-host
          hostPath:
            path: /usr/share/ca-certificates
        - name: k8s-config
          hostPath:
            path: /srv/k8s
coreos:
  etcd2:
    name: etcd-master
    listen-client-urls: http://0.0.0.0:2379,http://0.0.0.0:4001
    advertise-client-urls: http://$private_ipv4:2379,http://$private_ipv4:4001
    listen-peer-urls: http://$private_ipv4:2380
    initial-advertise-peer-urls: http://$private_ipv4:2380
    initial-cluster: etcd-master=http://$private_ipv4:2380
    initial-cluster-state: new
    initial-cluster-token: k8s-security-test
  units:
    - name: etcd2.service
      command: start
    - name: fleet.service
      mask: true
    - name: docker.service
      command: start
    - name: kubelet.service
      command: start
      content: |
        [Service]
        ExecStartPre=/usr/bin/mkdir -p /opt/bin
        ExecStartPre=/usr/bin/curl -s -L -o /opt/bin/kubelet -z /opt/bin/kubelet https://storage.googleapis.com/kubernetes-release/release/v1.5.6/bin/linux/amd64/kubelet
        ExecStartPre=/usr/bin/chmod +x /opt/bin/kubelet
        ExecStart=/opt/bin/kubelet \
          --api-servers=http://127.0.0.1:8080 \
          --config=/etc/kubernetes/manifests \
          --register-schedulable=false \
          --cadvisor-port=0
        ExecStartPost=/opt/bin/wupiao http://127.0.0.1:8080/version
        ExecStartPost=/usr/bin/curl \
          -XPOST \
          -H "Content-Type: application/json" \
          -d '{"apiVersion":"v1","kind":"Namespace","metadata":{"name":"kube-system"}}' \
          "http://127.0.0.1:8080/api/v1/namespaces"
        Restart=always
        RestartSec=10
        [Install]
        WantedBy=multi-user.target
  update:
    group: stable
    reboot-strategy: best-effort
```

### Kubernetes Node cloud-config (node.yml)

```
#cloud-config
---
write-files:
  - path: /etc/hosts
    permissions: '0644'
    content: |
      127.0.0.1 localhost node
  - path: /etc/kubernetes/kubeconfig.yml
    permissions: '0600'
    content: |
      apiVersion: v1
      kind: Config
      clusters:
      - name: default
        cluster:
          server: https://172.17.4.10:6443
          insecure-skip-tls-verify: true
      users:
      - name: default
        user:
          token: <insert service account token here>
      contexts:
      - context:
          cluster: default
          user: default
        name: default
      current-context: default
coreos:
  units:
    - name: etcd2.service
      mask: true
    - name: fleet.service
      mask: true
    - name: docker.service
      command: start
    - name: kubelet.service
      command: start
      content: |
        [Service]
        ExecStartPre=/usr/bin/mkdir -p /opt/bin
        ExecStartPre=/usr/bin/curl -s -L -o /opt/bin/kubelet -z /opt/bin/kubelet https://storage.googleapis.com/kubernetes-release/release/v1.5.6/bin/linux/amd64/kubelet
        ExecStartPre=/usr/bin/chmod +x /opt/bin/kubelet
        ExecStart=/opt/bin/kubelet \
          --kubeconfig=/etc/kubernetes/kubeconfig.yml \
          --api-servers=https://172.17.4.10:6443 \
          --hostname-override=minion \
          --host-network-sources="*" \
          --register-node=false \
          --enable-server=false \
          --read-only-port=0 \
          --cadvisor-port=0 \
          --healthz-port=0 \
          --v=8
        Restart=always
        RestartSec=10
        [Install]
        WantedBy=multi-user.target
  update:
    group: stable
    reboot-strategy: etcd-lock
```

## Node Requirements

The `kubelet` must be able to make a `list` and `watch` request against
the `nodes` resource. We're not exactly sure why this is (the requests
are only made at the very beginning of the `kubelet` startup process),
and it's unfortunate because the `list` request has the potential to
give a bad actor detailed information about every node running in the
cluster, including other customers' appliances.

If the `kubelet` is configured to register itself with the Kubernetes
master (which is the default configuration), then it must also be able
to make `create` requests against the `node` resource. This is
worrisome, since it's not possible to limit `create` requests to a
specific resource name.

> Kubernetes authorization is currently only able to limit resource
names to things resolvable from the URL, and the creation of a node
doesn't include the new node name in the URL (`POST /api/v1/nodes`).

We get around this by setting `--register-node=false` on the `kubelet`
service and creating the appliance node in Kubernetes during the
onboarding process.

The `kubelet` also needs to be able to make a `get` request against the
`nodes` resource, and more specifically against the resource name that
matches its hostname. For example, assuming a node has the hostname
`foobar`, the `kubelet` would need to be able to make the following
request:

```
GET /api/v1/nodes/foobar
```

While we can limit the `get` request against the `nodes` resource to the
resource name `foobar` in our RBAC policies, it's not really worth it
since the response provided for a `list` request against the `nodes`
resource provides the exact same information for a node that a `get`
request does.

Thus, one of our RBAC policies for the `nodes` resource looks like this:

```
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: node-monitor
rules:
  - resources: ["nodes"]
    verbs: ["get", "list", "watch"]
    apiGroups: [""]
```

Because all appliances have to be able to `get`, `list`, and `watch` the
`nodes` resource, and there's no way to limit the `list` and `watch`
verbs by specific resource name, and nodes aren't namespaced, we can
apply this role cluster-wide using the `system:serviceaccounts` subject.

```
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: monitor-appliance-nodes
subjects:
  - kind: Group
    name: system:serviceaccounts
roleRef:
  kind: ClusterRole
  name: node-monitor
  apiVersion: rbac.authorization.k8s.io/v1alpha1
```

The `kubelet` also has to post and patch `events` resources for nodes,
and since the `events` resource is namespaced but nodes are not, all
node events get written to the `default` namespace. Given this, we can
use a cluster-wide role definition for posting node events.

> The `patch` API calls for the `nodes` resources does specify a
resource name, but the resource name specified includes a hash on the
end of it (ie. `PATCH /api/v1/namespaces/default/events/foobar.147a14dc2fef13c8`).
Since RBAC role definitions do not support wildcards in resource names,
we cannot limit the `patch` calls to a specific node.

```
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: node-event-writer
rules:
  - resources: ["events"]
    verbs: ["create", "patch"]
    apiGroups: [""]
```

To keep appliances from posting events in another customer's namespace,
we limit the scope of node event posts to the `default` namespace with a
role binding (as opposed to a cluster-wide role binding).

```
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: write-appliance-node-events
  namespace: default
subjects:
  - kind: Group
    name: system:serviceaccounts
roleRef:
  kind: ClusterRole
  name: node-event-writer
  apiVersion: rbac.authorization.k8s.io/v1alpha1
```

Putting node status updates can be limited by resource name (ie. the
name of the node in Kubernetes). Since nodes aren't namespaced, we must
use a cluster-wide role here, but we need one per customer so we can
limit it to only the resources the customer owns, so we end up having to
*pollute the cluster-wide list of roles with per-customer definitions*.

```
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: {{NAMESPACE_NAME}}-node-handler
rules:
  - resources: ["nodes"]
    resourceNames: ["{{NODE_NAME}}"]
    verbs: ["get"]
    apiGroups: [""]
  - resources: ["nodes/status"]
    resourceNames: ["{{NODE_NAME}}"]
    verbs: ["update"]
    apiGroups: [""]
```

Again, since nodes aren't namespaced, we cannot use a simple role
binding to limit the custom node handler defined above to a specific
customer. We must again *pollute the cluster-wide list of role bindings
with per-customer definitions*.

```
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: {{NAMESPACE_NAME}}-handle-nodes
subjects:
  - kind: ServiceAccount
    name: default
    namespace: {{NAMESPACE_NAME}}
roleRef:
  kind: ClusterRole
  name: {{NAMESPACE_NAME}}-node-handler
  apiVersion: rbac.authorization.k8s.io/v1alpha1
```

## Pod Requirements

The `kubelet` must be able to make a `list` and `watch` request against
the `pods` resource, similar to the example below.

```
GET /api/v1/pods?fieldSelector=spec.nodeName%3Dfoobar&resourceVersion=0
```

Since subdivision of API calls isn't possible, we can't specify a
resource name for the `list` and `watch` verbs to use the appliance name
as the `spec.nodeName` in the request.

> I only include the ability to `list` and `watch` for `services` here
to keep the `kubelet` from generating too many logs about not being able
to list services. Dark Cubed appliances don't actually need service
information since they don't run `kube-proxy`.

```
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: pod-monitor
rules:
  - resources: ["pods", "services"]
    verbs: ["list", "watch"]
    apiGroups: [""]
```

Because all appliances have to be able to `list` and `watch` the `pods`
resource, and there's no way to limit the `list` and `watch` verbs by
specific resource name, and the API calls for listing and watching pods
are not namespaced, we can apply this role cluster-wide using the
`system:serviceaccounts` subject.

```
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: monitor-appliance-pods
subjects:
  - kind: Group
    name: system:serviceaccounts
roleRef:
  kind: ClusterRole
  name: pod-monitor
  apiVersion: rbac.authorization.k8s.io/v1alpha1
```

Once the `kubelet` knows what `pods`, `secrets`, and `configmap`
resources it needs access to (based on information it gets from the
`list` and `watch` calls), it has to be able to `get` those specific
resources. It must also be able to `update` the status of pods, as well
as `delete` pod resources once it successfully removes a running pod.
Lastly, the `kubelet` needs to be able to `create` and `patch`
pod-specific events.

```
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: pod-handler
rules:
  - resources: ["pods", "secrets", "configmaps"]
    verbs: ["get"]
    apiGroups: [""]
  - resources: ["pods"]
    verbs: ["delete"]
    apiGroups: [""]
  - resources: ["pods/status"]
    verbs: ["update"]
    apiGroups: [""]
  - resources: ["events"]
    verbs: ["create", "patch"]
    apiGroups: [""]
```

All of the resources defined above are namespaced, so we can use a role
binding with this cluster-wide role that limits actions taken on the
resources defined above to only the namespace owned by the customer.

```
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: handle-pods
  namespace: {{NAMESPACE_NAME}}
subjects:
  - kind: ServiceAccount
    name: default
    namespace: {{NAMESPACE_NAME}}
roleRef:
  kind: ClusterRole
  name: pod-handler
  apiVersion: rbac.authorization.k8s.io/v1alpha1
```

We have defined a third party resource in our Kubernetes cluster,
`status.foobar.io`. An instance of this resource gets created for each
appliance during the onboarding process, so the appliance itself only
needs to be able to `update` the already existing instance of the
resource.

The `apiGroups` option must be set to `foobar.io` (or `"*"`) for 3rd
party resources. An API group set to `""` means the ungrouped API, while
an API group set to `"*"` means all API groups.

```
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: status-writer
rules:
  - resources: ["statuses"]
    verbs: ["update"]
    apiGroups: ["foobar.io"]
```

Instances of third party resources in Kubernetes are namespaced, so we
can limit the `update` action to the customer's namespace to keep a
rogue actor from updating appliance statuses in other customer's
namespaces.

```
kind: RoleBinding
apiVersion: rbac.authorization.k8s.io/v1alpha1
metadata:
  name: write-statuses
  namespace: {{NAMESPACE_NAME}}
subjects:
  - kind: ServiceAccount
    name: default
    namespace: {{NAMESPACE_NAME}}
roleRef:
  kind: ClusterRole
  name: status-writer
  apiVersion: rbac.authorization.k8s.io/v1alpha1
```
