package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	corev1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&dynadotSolver{},
	)
}

// dynadotSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type dynadotSolver struct {
	client *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type dynadotProviderConfig struct {
	APIKeySecretRef corev1.SecretKeySelector `json:"apiKeySecretRef"`
	APIKey    string `json:"ApiKey"`
	APISecret string `json:"ApiSecret"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *dynadotSolver) Name() string {
	return "dynadot"
}


func (c *dynadotSolver) getApiToken(cfg *dynadotProviderConfig, ch *v1alpha1.ChallengeRequest) error {
	sec, err := c.client.CoreV1().
		Secrets(ch.ResourceNamespace).
		Get(context.TODO(), cfg.APIKeySecretRef.LocalObjectReference.Name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	secBytes, ok := sec.Data[cfg.APIKeySecretRef.Key]
	if !ok {
		return fmt.Errorf("key %q not found in secret \"%s/%s\"",
			cfg.APIKeySecretRef.Key,
			cfg.APIKeySecretRef.LocalObjectReference.Name,
			ch.ResourceNamespace)
	}

	token := strings.Split(string(secBytes), ":")
	cfg.APIKey = token[0]
	cfg.APISecret = token[1]

	return nil
}






func (s *dynadotSolver) dynadotClient(ch *v1alpha1.ChallengeRequest) (*DynadotClient, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	err = s.getApiToken(&cfg,ch)
	if err != nil {
		return nil, err
	}

	return NewDynadotClient(&cfg), nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *dynadotSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	dynadotClient, err := c.dynadotClient(ch)
	if err != nil {
		return err
	}
	domain := findDomainName(ch.ResolvedZone)
	subDomain := getSubDomain(domain, ch.ResolvedFQDN)
	target := ch.Key

	fmt.Printf("Got new challenge: %s\n", ch.ResolvedFQDN)


	return addTXTRecord(dynadotClient, domain, subDomain, target)
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (s *dynadotSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	dynadotClient, err := s.dynadotClient(ch)
	if err != nil {
		return err
	}
	domain := findDomainName(ch.ResolvedZone)
	dnsResponse, err := dynadotClient.GetDNSRecords(domain)
	if err != nil {
		fmt.Printf("Error getting DNS records: %v\n", err)
		return nil
	}

	dnsRecords := dnsResponse.Data
	var newRecords SetDNSRequest
	writeIndex := 0
    
    for readIndex := 0; readIndex < len(dnsRecords.Name_server_settings.Sub_domains); readIndex++ {
        record := dnsRecords.Name_server_settings.Sub_domains[readIndex]
        
        // Check if this record should be kept (doesn't match the criteria)
        if  record.RecordValue1 != ch.Key {
            dnsRecords.Name_server_settings.Sub_domains[writeIndex] = record
            writeIndex++
        }
    }
    
    // Truncate the slice to remove filtered elements
	newRecords.DNSMainList = ConvertMainDNSRecords(dnsRecords.Name_server_settings.Main_domains)
    newRecords.SubList = ConvertSubDNSRecords(dnsRecords.Name_server_settings.Sub_domains[:writeIndex])
	newRecords.TTL ,err = strconv.ParseInt(dnsRecords.Name_server_settings.TTL,10,64)
	if err != nil {
		fmt.Printf("Error parse TTL: %v\n", err)
	}

	response, err := dynadotClient.SetDNSRecords(domain, newRecords)
	if err != nil {
		fmt.Printf("Error setting all DNS records: %v\n", err)
	}

	
	fmt.Printf("Set All Response Message: %s\n", response.Message)

	
	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (s *dynadotSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}

	s.client = client
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (dynadotProviderConfig, error) {
	cfg := dynadotProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding dynadot config: %v", err)
	}

	return cfg, nil
}

func getSubDomain(domain, fqdn string) string {
	if idx := strings.Index(fqdn, "."+domain); idx != -1 {
		return fqdn[:idx]
	}

	return util.UnFqdn(fqdn)
}


func addTXTRecord(c *DynadotClient, domain, subDomain, target string) error{
	setDNSRequest := SetDNSRequest{
		DNSMainList: []MainDNSRecord{},
		SubList: []SubDNSRecord{
			{
				SubHost:      subDomain,
				RecordType:   "txt",
				RecordValue1: target,
			},
		},
		TTL:                    100,
		AddDNSToCurrentSetting: true,
	}
	
	response, err := c.SetDNSRecords(domain, setDNSRequest)
	if err != nil {
		fmt.Printf("Error setting DNS records: %v\n", err)
	}

	
	fmt.Printf("Add TXT Response Message: %s\n", response.Message)
	return nil
}

func findDomainName(zone string) string {
	authZone, err := util.FindZoneByFqdn(context.TODO(),zone, util.RecursiveNameservers)
	if err != nil {
		fmt.Printf("could not get zone by fqdn %v", err)
		return zone
	}
	fmt.Printf("Found Domain: %s\n", authZone)
	return util.UnFqdn(authZone)
}
