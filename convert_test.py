apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: <namespace>-deafault
  namespace: <namespace>
spec:
  endpointSelector: {}
  ingress:
    - fromEndpoints:
        - matchLabels:
            app.kubernetes.io/name: prometheus
            io.kubernetes.pod.namespace: d8-monitoring
      toPorts:
        - ports:
            - port: "15020"
              protocol: TCP
  egress:
    - toEndpoints:
        - matchLabels:
            io.kubernetes.pod.namespace: kube-system
            k8s-app: node-local-dns
      toPorts:
        - ports:
            - port: "53"
              protocol: "UDP"
          rules:
            dns:
              - matchPattern: "*"
    - toEndpoints:
        - matchLabels:
            app.kubernetes.io/instance: istiod
            io.kubernetes.pod.namespace: d8-istio
      toPorts:
        - ports:
            - port: "15012"
              protocol: TCP
