## Usage

[Helm](https://helm.sh) must be installed to use the charts.  Please refer to
Helm's [documentation](https://helm.sh/docs) to get started.

Once Helm has been set up correctly, add the repo as follows:

    helm repo add cert-manager-webhook-dynadot https://wylie39.github.io/cert-manager-webhook-dynadot

If you had already added this repo earlier, run `helm repo update` to retrieve
the latest versions of the packages.  You can then run `helm search repo
{alias}` to see the charts.

To install the cert-manager-webhook-dynadot chart:

    helm install --namespace cert-manager cert-manager-webhook-dynadot cert-manager-webhook-dynadot/cert-manager-webhook-dynadot

To uninstall the chart:

    helm delete cert-manager-webhook-dynadot

