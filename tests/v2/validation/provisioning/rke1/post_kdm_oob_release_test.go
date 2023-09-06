package rke1

import (
	"testing"

	"github.com/rancher/rancher/tests/framework/clients/rancher"
	"github.com/rancher/rancher/tests/framework/extensions/clusters/kubernetesversions"
	"github.com/rancher/rancher/tests/framework/extensions/provisioninginput"
	"github.com/rancher/rancher/tests/framework/pkg/config"
	"github.com/rancher/rancher/tests/framework/pkg/session"
	"github.com/rancher/rancher/tests/v2/validation/provisioning/permutations"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type KdmChecksTestSuite struct {
	suite.Suite
	session        *session.Session
	client         *rancher.Client
	ns             string
	clustersConfig *provisioninginput.Config
}

const (
	defaultNamespace             = "default"
	ProvisioningSteveResouceType = "provisioning.cattle.io.cluster"
)

func (k *KdmChecksTestSuite) TearDownSuite() {
	k.session.Cleanup()
}

func (k *KdmChecksTestSuite) SetupSuite() {
	testSession := session.NewSession()
	k.session = testSession

	k.ns = defaultNamespace

	k.clustersConfig = new(provisioninginput.Config)
	config.LoadConfig(provisioninginput.ConfigurationFileKey, k.clustersConfig)

	client, err := rancher.NewClient("", testSession)
	require.NoError(k.T(), err)

	k.client = client
}

func (k *KdmChecksTestSuite) TestRKE1K8sVersions() {
	logrus.Infof("checking for valid k8s versions..")
	require.GreaterOrEqual(k.T(), len(k.clustersConfig.RKE1KubernetesVersions), 1)
	// fetching all available k8s versions from rancher
	releasedK8sVersions, _ := kubernetesversions.ListRKE1AllVersions(k.client)
	logrus.Info("expected k8s versions : ", k.clustersConfig.RKE1KubernetesVersions)
	logrus.Info("k8s versions available on rancher server : ", releasedK8sVersions)
	for _, expectedK8sVersion := range k.clustersConfig.RKE1KubernetesVersions {
		require.Contains(k.T(), releasedK8sVersions, expectedK8sVersion)
	}
}

func (k *KdmChecksTestSuite) TestProvisioningSingleNodeRKE1Clusters() {
	require.GreaterOrEqual(k.T(), len(k.clustersConfig.Providers), 1)
	require.GreaterOrEqual(k.T(), len(k.clustersConfig.CNIs), 1)

	subSession := k.session.NewSession()
	defer subSession.Cleanup()

	client, err := k.client.WithSession(subSession)
	require.NoError(k.T(), err)
	permutations.RunTestPermutations(&k.Suite, "oobRelease-", client, k.clustersConfig, permutations.RKE1ProvisionCluster, nil, nil)

}

func TestPostKdmOutOfBandReleaseChecks(t *testing.T) {
	suite.Run(t, new(KdmChecksTestSuite))
}