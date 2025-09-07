# Dynadot Webhook for Cert Manager
This is a webhook solver for Dynadot

## Installation
### Prerequisites
Install cert-manager. You can find more info [here](https://cert-manager.io/docs/installation/)

## Install Webhook
To install the chart:  
`helm repo add cert-manager-webhook-dynadot https://wylie39.github.io/cert-manager-webhook-dynadot`  
`helm install --namespace cert-manager cert-manager-webhook-dynadot cert-manager-webhook-dynadot/cert-manager-webhook-dynadot`

Or to use it from a local copy of the repo  
`helm install --namespace cert-manager cert-manager-webhook-dynadot deploy/cert-manager-webhook-dynadot/`

## Create Issuer
Create a ClusterIssuer
```
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt
spec:
  acme:
    # The ACME server URL
    server: https://acme-v02.api.letsencrypt.org/directory

    # Email address used for ACME registration
    email: <EMAIL> # REPLACE THIS WITH YOUR EMAIL!!!

    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt

    solvers:
      - dns01:
          webhook:
            groupName: acme.wylief.dev #If you change this, make sure to update values.yaml
            solverName: dynadot
            config:
              apiKeySecretRef: 
                name: dynadot-credentials
                key: token
```

## Credentials
You can get your api key and your application secret in the Dynadot console, more info [here](https://www.dynadot.com/domain/api-document) 
```
apiVersion: v1
kind: Secret
metadata:
  name: dynadot-credentials
type: Opaque
data:
  token: <your-api-key>:<your-application-secret> base64 encode this
```

## Get a certificate
```
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: example-cert
  namespace: cert-manager
spec:
  commonName: example.com
  dnsNames:
    - example.com
  issuerRef:
    name: letsencrypt
    kind: ClusterIssuer
  secretName: example-cert
```

### Running the test suite

All DNS providers **must** run the DNS01 provider conformance testing suite,
else they will have undetermined behaviour when used with cert-manager.


You can run the test suite with:

```bash
$ TEST_ZONE_NAME=example.com. make test
```

## Thanks
Based on [webhook-example](https://github.com/cert-manager/webhook-example/tree/master)  
[cert-manager-webhook-hetzner](https://github.com/vadimkim/cert-manager-webhook-hetzner/tree/master) and [cert-manager-webhook-ovh](https://github.com/baarde/cert-manager-webhook-ovh?tab=readme-ov-file) were referenced as well


