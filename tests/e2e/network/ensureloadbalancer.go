/*
Copyright 2019 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/services/network/mgmt/2022-07-01/network"
	aznetwork "github.com/Azure/azure-sdk-for-go/services/network/mgmt/2022-07-01/network"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/apimachinery/pkg/util/wait"
	clientset "k8s.io/client-go/kubernetes"
	cloudprovider "k8s.io/cloud-provider"
	"k8s.io/utils/pointer"

	"sigs.k8s.io/cloud-provider-azure/pkg/consts"
	"sigs.k8s.io/cloud-provider-azure/tests/e2e/utils"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

const (
	testBaseName       = "service-lb"
	testServiceName    = "service-lb-test"
	testDeploymentName = "deployment-lb-test"
)

var (
	serviceAnnotationLoadBalancerInternalFalse = map[string]string{
		consts.ServiceAnnotationLoadBalancerInternal: "false",
	}
	serviceAnnotationLoadBalancerInternalTrue = map[string]string{
		consts.ServiceAnnotationLoadBalancerInternal: "true",
	}
	serviceAnnotationDisableLoadBalancerFloatingIP = map[string]string{
		consts.ServiceAnnotationDisableLoadBalancerFloatingIP: "true",
	}
)

var _ = Describe("Ensure LoadBalancer", Label("TESTTEST"), func() {
	basename := testBaseName

	var cs clientset.Interface
	var ns *v1.Namespace
	var tc *utils.AzureTestClient
	var deployment *appsv1.Deployment

	labels := map[string]string{
		"app": testServiceName,
	}

	BeforeEach(func() {
		var err error
		cs, err = utils.CreateKubeClientSet()
		Expect(err).NotTo(HaveOccurred())

		ns, err = utils.CreateTestingNamespace(basename, cs)
		Expect(err).NotTo(HaveOccurred())

		tc, err = utils.CreateAzureTestClient()
		Expect(err).NotTo(HaveOccurred())

		utils.Logf("Creating deployment %s", testDeploymentName)
		deployment = createServerDeploymentManifest(testDeploymentName, labels)
		_, err = cs.AppsV1().Deployments(ns.Name).Create(context.TODO(), deployment, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if cs != nil && ns != nil {
			err := cs.AppsV1().Deployments(ns.Name).Delete(context.TODO(), testDeploymentName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			err = utils.DeleteNamespace(cs, ns.Name)
			Expect(err).NotTo(HaveOccurred())
		}

		cs = nil
		ns = nil
		tc = nil
	})

	It("should support mixed protocol services", func() {
		utils.Logf("Updating deployment %s", testDeploymentName)
		tcpPort := int32(serverPort)
		udpPort := int32(testingPort)
		deployment := createDeploymentManifest(testDeploymentName, labels, &tcpPort, &udpPort)
		_, err := cs.AppsV1().Deployments(ns.Name).Update(context.TODO(), deployment, metav1.UpdateOptions{})
		Expect(err).NotTo(HaveOccurred())

		By("creating a mixed protocol service")
		mixedProtocolPorts := []v1.ServicePort{
			{
				Name:       "tcp",
				Port:       serverPort,
				TargetPort: intstr.FromInt(serverPort),
				Protocol:   v1.ProtocolTCP,
			},
			{
				Name:       "udp",
				Port:       testingPort,
				TargetPort: intstr.FromInt(testingPort),
				Protocol:   v1.ProtocolUDP,
			},
		}
		service := utils.CreateLoadBalancerServiceManifest(testServiceName, nil, labels, ns.Name, mixedProtocolPorts)
		_, err = cs.CoreV1().Services(ns.Name).Create(context.TODO(), service, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		ips, err := utils.WaitServiceExposureAndValidateConnectivity(cs, tc.IPFamily, ns.Name, testServiceName, []string{})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(ips)).NotTo(BeZero())
		ip := ips[0]

		By("checking load balancing rules")
		foundTCP, foundUDP := false, false
		lb := getAzureLoadBalancerFromPIP(tc, ip, tc.GetResourceGroup(), "")
		for _, rule := range *lb.LoadBalancingRules {
			switch {
			case strings.EqualFold(string(rule.Protocol), string(v1.ProtocolTCP)):
				if pointer.Int32Deref(rule.FrontendPort, 0) == serverPort {
					foundTCP = true
				}
			case strings.EqualFold(string(rule.Protocol), string(v1.ProtocolUDP)):
				if pointer.Int32Deref(rule.FrontendPort, 0) == testingPort {
					foundUDP = true
				}
			}
		}
		Expect(foundTCP).To(BeTrue())
		Expect(foundUDP).To(BeTrue())
	})

})

var _ = Describe("EnsureLoadBalancer should not update any resources when service config is not changed", Label(utils.TestSuiteLabelLB), func() {
	basename := testBaseName

	var cs clientset.Interface
	var ns *v1.Namespace
	var tc *utils.AzureTestClient
	var deployment *appsv1.Deployment

	labels := map[string]string{
		"app": testServiceName,
	}
	ports := []v1.ServicePort{{
		Port:       serverPort,
		TargetPort: intstr.FromInt(serverPort),
	}}

	BeforeEach(func() {
		var err error
		cs, err = utils.CreateKubeClientSet()
		Expect(err).NotTo(HaveOccurred())

		ns, err = utils.CreateTestingNamespace(basename, cs)
		Expect(err).NotTo(HaveOccurred())

		tc, err = utils.CreateAzureTestClient()
		Expect(err).NotTo(HaveOccurred())

		utils.Logf("Creating deployment %s", testDeploymentName)
		deployment = createServerDeploymentManifest(testDeploymentName, labels)
		_, err = cs.AppsV1().Deployments(ns.Name).Create(context.TODO(), deployment, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
	})

	AfterEach(func() {
		if cs != nil && ns != nil {
			err := cs.AppsV1().Deployments(ns.Name).Delete(context.TODO(), testDeploymentName, metav1.DeleteOptions{})
			Expect(err).NotTo(HaveOccurred())

			err = utils.DeleteNamespace(cs, ns.Name)
			Expect(err).NotTo(HaveOccurred())
		}

		cs = nil
		ns = nil
		tc = nil
	})

	It("should respect service with various configurations", func() {
		By("Creating a service and expose it")
		serviceDomainNamePrefix := testServiceName + string(uuid.NewUUID())
		annotation := map[string]string{
			consts.ServiceAnnotationDNSLabelName:                       serviceDomainNamePrefix,
			consts.ServiceAnnotationLoadBalancerIdleTimeout:            "20",
			consts.ServiceAnnotationLoadBalancerHealthProbeProtocol:    "HTTP",
			consts.ServiceAnnotationLoadBalancerHealthProbeRequestPath: "/healthtz",
			consts.ServiceAnnotationLoadBalancerHealthProbeInterval:    "10",
			consts.ServiceAnnotationLoadBalancerHealthProbeNumOfProbe:  "8",
		}

		if strings.EqualFold(os.Getenv(utils.LoadBalancerSkuEnv), string(network.PublicIPAddressSkuNameStandard)) &&
			tc.IPFamily == utils.IPv4 {
			// Routing preference is only supported in standard public IPs
			annotation[consts.ServiceAnnotationIPTagsForPublicIP] = "RoutingPreference=Internet"
		}

		ips := createAndExposeDefaultServiceWithAnnotation(cs, tc.IPFamily, testServiceName, ns.Name, labels, annotation, ports)
		Expect(len(ips)).NotTo(BeZero())
		ip := ips[0]
		service, err := cs.CoreV1().Services(ns.Name).Get(context.TODO(), testServiceName, metav1.GetOptions{})
		defer func() {
			By("Cleaning up")
			err := utils.DeleteService(cs, ns.Name, testServiceName)
			Expect(err).NotTo(HaveOccurred())
		}()
		Expect(err).NotTo(HaveOccurred())

		By("Update the service and without significant changes and compare etags")
		updateServiceAndCompareEtags(tc, cs, ns, service, ip, false)
	})

	It("should respect service with BYO public IP with various configurations", func() {
		By("Creating BYO public IPs")
		ipNameBase := basename + "-public-IP" + string(uuid.NewUUID())[0:4]
		v4Enabled, v6Enabled := utils.IfIPFamiliesEnabled(tc.IPFamily)
		targetIPs := []string{}
		deleteFuncs := []func(){}
		if v4Enabled {
			targetIP, deleteFunc := createPIP(tc, ipNameBase, false)
			targetIPs = append(targetIPs, targetIP)
			deleteFuncs = append(deleteFuncs, deleteFunc)
		}
		if v6Enabled {
			targetIP, deleteFunc := createPIP(tc, ipNameBase, true)
			targetIPs = append(targetIPs, targetIP)
			deleteFuncs = append(deleteFuncs, deleteFunc)
		}
		defer func() {
			By("Clean up PIPs")
			for _, deleteFunc := range deleteFuncs {
				deleteFunc()
			}
		}()

		customHealthProbeConfigPrefix := "service.beta.kubernetes.io/port_" + strconv.Itoa(int(ports[0].Port)) + "_health-probe_"
		By("Creating a service and expose it")
		annotation := map[string]string{
			consts.ServiceAnnotationDenyAllExceptLoadBalancerSourceRanges: "true",
			customHealthProbeConfigPrefix + "interval":                    "10",
			customHealthProbeConfigPrefix + "num-of-probe":                "6",
			customHealthProbeConfigPrefix + "request-path":                "/healthtz",
		}
		if tc.IPFamily == utils.DualStack {
			annotation[consts.ServiceAnnotationPIPNameDualStack[false]] = utils.GetNameWithSuffix(ipNameBase, utils.Suffixes[false])
			annotation[consts.ServiceAnnotationPIPNameDualStack[true]] = utils.GetNameWithSuffix(ipNameBase, utils.Suffixes[true])
		} else {
			annotation[consts.ServiceAnnotationPIPNameDualStack[false]] = utils.GetNameWithSuffix(ipNameBase, utils.Suffixes[tc.IPFamily == utils.IPv6])
		}

		service := utils.CreateLoadBalancerServiceManifest(testServiceName, annotation, labels, ns.Name, ports)
		service.Spec.LoadBalancerSourceRanges = []string{}
		if v4Enabled {
			service.Spec.LoadBalancerSourceRanges = append(service.Spec.LoadBalancerSourceRanges, "0.0.0.0/0")
		}
		if v6Enabled {
			service.Spec.LoadBalancerSourceRanges = append(service.Spec.LoadBalancerSourceRanges, "::/0")
		}
		service.Spec.SessionAffinity = "ClientIP"
		_, err := cs.CoreV1().Services(ns.Name).Create(context.TODO(), service, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		_, err = utils.WaitServiceExposureAndValidateConnectivity(cs, tc.IPFamily, ns.Name, testServiceName, targetIPs)
		Expect(err).NotTo(HaveOccurred())

		service, err = cs.CoreV1().Services(ns.Name).Get(context.TODO(), testServiceName, metav1.GetOptions{})
		defer func() {
			By("Cleaning up")
			err := utils.DeleteService(cs, ns.Name, testServiceName)
			Expect(err).NotTo(HaveOccurred())
		}()
		Expect(err).NotTo(HaveOccurred())

		By("Update the service and without significant changes and compare etags")
		Expect(len(targetIPs)).NotTo(BeZero())
		updateServiceAndCompareEtags(tc, cs, ns, service, targetIPs[0], false)
	})

	It("should respect service with BYO public IP prefix with various configurations", func() {
		if !strings.EqualFold(os.Getenv(utils.LoadBalancerSkuEnv), string(network.PublicIPAddressSkuNameStandard)) {
			Skip("pip-prefix-id only work with Standard Load Balancer")
		}

		annotation := map[string]string{
			consts.ServiceAnnotationDisableLoadBalancerFloatingIP: "true",
			consts.ServiceAnnotationSharedSecurityRule:            "true",
		}

		By("Creating BYO public IP prefixes")
		prefixNameBase := "prefix"
		v4Enabled, v6Enabled := utils.IfIPFamiliesEnabled(tc.IPFamily)
		createPIPPrefix := func(isIPv6 bool) func() {
			prefixName := utils.GetNameWithSuffix(prefixNameBase, utils.Suffixes[isIPv6])
			prefix, err := utils.WaitCreatePIPPrefix(tc, prefixName, tc.GetResourceGroup(), defaultPublicIPPrefix(prefixName, isIPv6))
			deleteFunc := func() {
				Expect(utils.DeletePIPPrefixWithRetry(tc, prefixName)).NotTo(HaveOccurred())
			}
			Expect(err).NotTo(HaveOccurred())

			if tc.IPFamily == utils.DualStack {
				annotation[consts.ServiceAnnotationPIPPrefixIDDualStack[isIPv6]] = pointer.StringDeref(prefix.ID, "")
			} else {
				annotation[consts.ServiceAnnotationPIPPrefixIDDualStack[false]] = pointer.StringDeref(prefix.ID, "")
			}
			return deleteFunc
		}
		deleteFuncs := []func(){}
		if v4Enabled {
			deleteFuncs = append(deleteFuncs, createPIPPrefix(false))
		}
		if v6Enabled {
			deleteFuncs = append(deleteFuncs, createPIPPrefix(true))
		}
		defer func() {
			for _, deleteFunc := range deleteFuncs {
				deleteFunc()
			}
		}()

		By("Creating a service and expose it")
		service := utils.CreateLoadBalancerServiceManifest(testServiceName, annotation, labels, ns.Name, ports)
		service.Spec.ExternalTrafficPolicy = "Local"
		_, err := cs.CoreV1().Services(ns.Name).Create(context.TODO(), service, metav1.CreateOptions{})
		Expect(err).NotTo(HaveOccurred())
		ips, err := utils.WaitServiceExposureAndValidateConnectivity(cs, tc.IPFamily, ns.Name, testServiceName, []string{})
		Expect(err).NotTo(HaveOccurred())
		Expect(len(ips)).NotTo(BeZero())
		ip := ips[0]

		service, err = cs.CoreV1().Services(ns.Name).Get(context.TODO(), testServiceName, metav1.GetOptions{})
		defer func() {
			By("Cleaning up")
			err := utils.DeleteService(cs, ns.Name, testServiceName)
			Expect(err).NotTo(HaveOccurred())
		}()
		Expect(err).NotTo(HaveOccurred())

		By("Update the service and without significant changes and compare etags")
		updateServiceAndCompareEtags(tc, cs, ns, service, ip, false)
	})

	It("should respect internal service with various configurations", func() {
		By("Creating a subnet for ilb frontend ip")
		subnetName := "testSubnet"
		subnet, isNew := createNewSubnet(tc, subnetName)
		Expect(pointer.StringDeref(subnet.Name, "")).To(Equal(subnetName))
		if isNew {
			defer func() {
				utils.Logf("cleaning up test subnet %s", subnetName)
				vNet, err := tc.GetClusterVirtualNetwork()
				Expect(err).NotTo(HaveOccurred())
				err = tc.DeleteSubnet(pointer.StringDeref(vNet.Name, ""), subnetName)
				Expect(err).NotTo(HaveOccurred())
			}()
		}

		By("Creating a service and expose it")
		annotation := map[string]string{
			consts.ServiceAnnotationLoadBalancerInternal:                    "true",
			consts.ServiceAnnotationLoadBalancerInternalSubnet:              subnetName,
			consts.ServiceAnnotationLoadBalancerEnableHighAvailabilityPorts: "true",
		}
		ips := createAndExposeDefaultServiceWithAnnotation(cs, tc.IPFamily, testServiceName, ns.Name, labels, annotation, ports)
		service, err := cs.CoreV1().Services(ns.Name).Get(context.TODO(), testServiceName, metav1.GetOptions{})
		defer func() {
			By("Cleaning up")
			err := utils.DeleteService(cs, ns.Name, testServiceName)
			Expect(err).NotTo(HaveOccurred())
		}()
		Expect(err).NotTo(HaveOccurred())
		Expect(len(ips)).NotTo(BeZero())
		ip := ips[0]

		By("Update the service and without significant changes and compare etags")
		updateServiceAndCompareEtags(tc, cs, ns, service, ip, true)
	})
})

func addDummyAnnotationWithServiceName(cs clientset.Interface, namespace string, serviceName string) {
	service, err := cs.CoreV1().Services(namespace).Get(context.TODO(), serviceName, metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred())
	addDummyAnnotationWithService(cs, namespace, service)
}

func addDummyAnnotationWithService(cs clientset.Interface, namespace string, service *v1.Service) {
	utils.Logf("Adding a dummy annotation to trigger Service reconciliation")
	Expect(service).NotTo(BeNil())
	annotation := service.GetAnnotations()
	if annotation == nil {
		annotation = make(map[string]string)
	}
	// e2e test should not have 100+ dummy annotations.
	for i := 0; i < 100; i++ {
		if _, ok := annotation["dummy-annotation"+strconv.Itoa(i)]; !ok {
			annotation["dummy-annotation"+strconv.Itoa(i)] = "dummy"
			break
		}
	}
	service = updateServiceAnnotation(service, annotation)
	utils.Logf("Service's annotations: %v", annotation)
	_, err := cs.CoreV1().Services(namespace).Update(context.TODO(), service, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred())
}

func updateServiceAndCompareEtags(tc *utils.AzureTestClient, cs clientset.Interface, ns *v1.Namespace, service *v1.Service, ip string, isInternal bool) {
	utils.Logf("Retrieving etags from resources")
	lbEtag, nsgEtag, pipEtag := getResourceEtags(tc, ip, cloudprovider.DefaultLoadBalancerName(service), isInternal)

	addDummyAnnotationWithService(cs, ns.Name, service)
	ips, err := utils.WaitServiceExposureAndValidateConnectivity(cs, tc.IPFamily, ns.Name, testServiceName, []string{})
	Expect(err).NotTo(HaveOccurred())
	Expect(len(ips)).NotTo(BeZero())
	ip = ips[0]

	utils.Logf("Checking etags are not changed")
	newLbEtag, newNsgEtag, newPipEtag := getResourceEtags(tc, ip, cloudprovider.DefaultLoadBalancerName(service), isInternal)
	Expect(lbEtag).To(Equal(newLbEtag), "lb etag")
	Expect(nsgEtag).To(Equal(newNsgEtag), "nsg etag")
	Expect(pipEtag).To(Equal(newPipEtag), "pip etag")
}

func createNewSubnet(tc *utils.AzureTestClient, subnetName string) (*network.Subnet, bool) {
	vNet, err := tc.GetClusterVirtualNetwork()
	Expect(err).NotTo(HaveOccurred())

	var subnetToReturn *network.Subnet
	isNew := false
	for i := range *vNet.Subnets {
		existingSubnet := (*vNet.Subnets)[i]
		if *existingSubnet.Name == subnetName {
			By("Test subnet exists, skip creating")
			subnetToReturn = &existingSubnet
			break
		}
	}

	if subnetToReturn == nil {
		By("Test subnet doesn't exist. Creating a new one...")
		isNew = true
		newSubnetCIDRs, err := utils.GetNextSubnetCIDRs(vNet, tc.IPFamily)
		Expect(err).NotTo(HaveOccurred())
		newSubnetCIDRStrs := []string{}
		for _, newSubnetCIDR := range newSubnetCIDRs {
			newSubnetCIDRStrs = append(newSubnetCIDRStrs, newSubnetCIDR.String())
		}
		newSubnet, err := tc.CreateSubnet(vNet, &subnetName, &newSubnetCIDRStrs, true)
		Expect(err).NotTo(HaveOccurred())
		subnetToReturn = &newSubnet
	}

	return subnetToReturn, isNew
}

func getResourceEtags(tc *utils.AzureTestClient, ip, nsgRulePrefix string, internal bool) (lbEtag, nsgEtag, pipEtag string) {
	if internal {
		lbEtag = pointer.StringDeref(getAzureInternalLoadBalancerFromPrivateIP(tc, ip, "").Etag, "")
	} else {
		lbEtag = pointer.StringDeref(getAzureLoadBalancerFromPIP(tc, ip, tc.GetResourceGroup(), "").Etag, "")
	}

	nsgs, err := tc.GetClusterSecurityGroups()
	Expect(err).NotTo(HaveOccurred())
	for _, nsg := range nsgs {
		if nsg.SecurityRules == nil {
			continue
		}
		for _, securityRule := range *nsg.SecurityRules {
			utils.Logf("Checking security rule %q", pointer.StringDeref(securityRule.Name, ""))
			if strings.HasPrefix(pointer.StringDeref(securityRule.Name, ""), nsgRulePrefix) {
				nsgEtag = pointer.StringDeref(nsg.Etag, "")
				break
			}
		}
	}

	if !internal {
		pip, err := tc.GetPublicIPFromAddress(tc.GetResourceGroup(), ip)
		Expect(err).NotTo(HaveOccurred())
		pipEtag = pointer.StringDeref(pip.Etag, "")
	}
	utils.Logf("Got resource etags: lbEtag: %s; nsgEtag: %s, pipEtag: %s", lbEtag, nsgEtag, pipEtag)
	return
}

func getAzureInternalLoadBalancerFromPrivateIP(tc *utils.AzureTestClient, ip, lbResourceGroup string) *network.LoadBalancer {
	if lbResourceGroup == "" {
		lbResourceGroup = tc.GetResourceGroup()
	}
	utils.Logf("Listing all LBs in the resourceGroup " + lbResourceGroup)
	lbList, err := tc.ListLoadBalancers(lbResourceGroup)
	Expect(err).NotTo(HaveOccurred())

	var ilb *network.LoadBalancer
	utils.Logf("Looking for internal load balancer frontend config ID with private ip as frontend")
	for i := range lbList {
		lb := lbList[i]
		for _, fipconfig := range *lb.FrontendIPConfigurations {
			if fipconfig.PrivateIPAddress != nil &&
				*fipconfig.PrivateIPAddress == ip {
				ilb = &lb
				break
			}
		}
	}
	Expect(ilb).NotTo(BeNil())
	return ilb
}

func waitForNodesInLBBackendPool(tc *utils.AzureTestClient, ip string, expectedNum int) error {
	return wait.PollImmediate(10*time.Second, 10*time.Minute, func() (done bool, err error) {
		lb := getAzureLoadBalancerFromPIP(tc, ip, tc.GetResourceGroup(), "")
		if lb.Sku != nil && lb.Sku.Name == aznetwork.LoadBalancerSkuNameBasic {
			// basic lb
			idxes := getLBBackendPoolIndex(lb)
			if len(idxes) == 0 {
				return false, errors.New("no backend pool found")
			}
			failed := false
			for _, idx := range idxes {
				bp := (*lb.BackendAddressPools)[idx]
				lbBackendPoolIPConfigs := bp.BackendIPConfigurations
				ipConfigNum := 0
				if lbBackendPoolIPConfigs != nil {
					ipConfigNum = len(*lbBackendPoolIPConfigs)
				}
				if expectedNum == ipConfigNum {
					utils.Logf("Number of IP configs in the LB backend pool %q matches expected number %d. Success", *bp.Name, expectedNum)
				} else {
					utils.Logf("Number of IP configs: %d in the LB backend pool %q, expected %d, will retry soon", ipConfigNum, *bp.Name, expectedNum)
					failed = true
				}
			}
			return !failed, nil
		}
		// SLB
		idxes := getLBBackendPoolIndex(lb)
		if len(idxes) == 0 {
			return false, errors.New("no backend pool found")
		}
		failed := false
		for _, idx := range idxes {
			bp := (*lb.BackendAddressPools)[idx]
			lbBackendPoolIPs := bp.LoadBalancerBackendAddresses
			ipNum := 0
			if lbBackendPoolIPs != nil {
				if utils.IsAutoscalingAKSCluster() {
					// Autoscaling tests don't include IP based LB.
					for _, ip := range *lbBackendPoolIPs {
						if ip.LoadBalancerBackendAddressPropertiesFormat == nil ||
							ip.LoadBalancerBackendAddressPropertiesFormat.NetworkInterfaceIPConfiguration == nil {
							return false, fmt.Errorf("LB backendPool address's NIC IP config ID is nil")
						}
						ipConfigID := pointer.StringDeref(ip.LoadBalancerBackendAddressPropertiesFormat.NetworkInterfaceIPConfiguration.ID, "")
						if !strings.Contains(ipConfigID, utils.SystemPool) {
							ipNum++
						}
					}
				} else {
					ipNum = len(*lbBackendPoolIPs)
				}
			}
			if ipNum == expectedNum {
				utils.Logf("Number of IPs in the LB backend pool %q matches expected number %d. Success", *bp.Name, expectedNum)
			} else {
				utils.Logf("Number of IPs: %d in the LB backend pool %q, expected %d, will retry soon", ipNum, *bp.Name, expectedNum)
				failed = true
			}
		}
		return !failed, nil
	})
}

func judgeInternal(service v1.Service) bool {
	return service.Annotations[consts.ServiceAnnotationLoadBalancerInternal] == utils.TrueValue
}

func getLBBackendPoolIndex(lb *aznetwork.LoadBalancer) []int {
	idxes := []int{}
	for index, backendPool := range *lb.BackendAddressPools {
		if !strings.Contains(strings.ToLower(*backendPool.Name), "outboundbackendpool") {
			idxes = append(idxes, index)
		}
	}
	return idxes
}

func updateServiceLBIPs(service *v1.Service, isInternal bool, ips []string) (result *v1.Service) {
	result = service
	if result == nil {
		return
	}
	if result.Annotations == nil {
		result.Annotations = map[string]string{}
	}
	for _, ip := range ips {
		isIPv6 := net.ParseIP(ip).To4() == nil
		result.Annotations[consts.ServiceAnnotationLoadBalancerIPDualStack[isIPv6]] = ip
	}

	if judgeInternal(*service) == isInternal {
		return
	}
	if isInternal {
		result.Annotations[consts.ServiceAnnotationLoadBalancerInternal] = utils.TrueValue
	} else {
		delete(result.Annotations, consts.ServiceAnnotationLoadBalancerInternal)
	}
	return
}

func updateServicePIPNames(ipFamily utils.IPFamily, service *v1.Service, pipNames []string) *v1.Service {
	if service.Annotations == nil {
		service.Annotations = map[string]string{}
	}

	isDualStack := ipFamily == utils.DualStack
	for _, pipName := range pipNames {
		if !isDualStack || !strings.HasSuffix(pipName, "-IPv6") {
			service.Annotations[consts.ServiceAnnotationPIPNameDualStack[consts.IPVersionIPv4]] = pipName
		} else {
			service.Annotations[consts.ServiceAnnotationPIPNameDualStack[consts.IPVersionIPv6]] = pipName
		}
	}

	return service
}

func defaultPublicIPAddress(ipName string, isIPv6 bool) aznetwork.PublicIPAddress {
	// The default sku for LoadBalancer and PublicIP is basic.
	skuName := aznetwork.PublicIPAddressSkuNameBasic
	if skuEnv := os.Getenv(utils.LoadBalancerSkuEnv); skuEnv != "" {
		if strings.EqualFold(skuEnv, string(aznetwork.PublicIPAddressSkuNameStandard)) {
			skuName = aznetwork.PublicIPAddressSkuNameStandard
		}
	}
	pip := aznetwork.PublicIPAddress{
		Name:     pointer.String(ipName),
		Location: pointer.String(os.Getenv(utils.ClusterLocationEnv)),
		Sku: &aznetwork.PublicIPAddressSku{
			Name: skuName,
		},
		PublicIPAddressPropertiesFormat: &aznetwork.PublicIPAddressPropertiesFormat{
			PublicIPAllocationMethod: aznetwork.Static,
		},
	}
	if isIPv6 {
		pip.PublicIPAddressPropertiesFormat.PublicIPAddressVersion = network.IPv6
	}
	return pip
}

func defaultPublicIPPrefix(name string, isIPv6 bool) aznetwork.PublicIPPrefix {
	pipAddrVersion := aznetwork.IPv4
	var prefixLen int32 = 28
	if isIPv6 {
		pipAddrVersion = aznetwork.IPv6
		prefixLen = 124
	}
	return aznetwork.PublicIPPrefix{
		Name:     pointer.String(name),
		Location: pointer.String(os.Getenv(utils.ClusterLocationEnv)),
		Sku: &aznetwork.PublicIPPrefixSku{
			Name: aznetwork.PublicIPPrefixSkuNameStandard,
		},
		PublicIPPrefixPropertiesFormat: &aznetwork.PublicIPPrefixPropertiesFormat{
			PrefixLength:           pointer.Int32(prefixLen),
			PublicIPAddressVersion: pipAddrVersion,
		},
	}
}

func createPIP(tc *utils.AzureTestClient, ipNameBase string, isIPv6 bool) (string, func()) {
	ipName := utils.GetNameWithSuffix(ipNameBase, utils.Suffixes[isIPv6])
	pip, err := utils.WaitCreatePIP(tc, ipName, tc.GetResourceGroup(), defaultPublicIPAddress(ipName, isIPv6))
	Expect(err).NotTo(HaveOccurred())
	targetIP := pointer.StringDeref(pip.IPAddress, "")
	utils.Logf("Created PIP to %s", targetIP)
	return targetIP, func() {
		By("Cleaning up PIP")
		err = utils.DeletePIPWithRetry(tc, ipName, "")
		Expect(err).NotTo(HaveOccurred())
	}
}
