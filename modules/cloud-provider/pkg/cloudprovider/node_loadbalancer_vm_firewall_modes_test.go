package cloudprovider

import "testing"

// firewallModeScenario is one scenario of the public-node-local state machine
// that holds on either firewall mode.
type firewallModeScenario struct {
	name string
	run  func(*testing.T)
}

// publicNodeLocalModeScenarios are the existing scenarios of the Service state
// machine, run unchanged on both firewall modes: incremental add and remove, the
// endpoint grace, the spaced all-gone confirmation, child repair, pool switch,
// port add and removal, range change, mixed change, revert, retarget, pool and
// policy together, restart at every step and the Nth provider failure. Their
// fixtures follow publicNodeLocalTestMode; the edge invariant of
// requireVMEdgeSafe is checked on every pass they drive through the shared step
// helpers, and the firewall limit is checked on every attach when they end.
func publicNodeLocalModeScenarios() []firewallModeScenario {
	return []firewallModeScenario{
		{"add node", TestPublicNodeLocalAddNodeKeepsExistingIPsPublished},
		{"endpoint gone removes after grace", TestPublicNodeLocalEndpointGoneRemovesAfterGrace},
		{"zero ready endpoints holds", TestPublicNodeLocalZeroReadyEndpointsHoldsPublication},
		{"unverified published node is held", TestPublicNodeLocalUnverifiedPublishedNodeIsHeld},
		{"all published nodes gone withdraws", TestPublicNodeLocalAllPublishedNodesGoneWithdraws},
		{"grace restarts when an endpoint returns", TestPublicNodeLocalGraceRestartsWhenAnEndpointReturns},
		{"verified ineligible node is removed", TestPublicNodeLocalVerifiedIneligiblePublishedNodeIsRemoved},
		{"all-gone needs spaced confirmation", TestPublicNodeLocalFullWithdrawNeedsSpacedConfirmationFromCloudOnlyEvidence},
		{"all-gone confirmation resets", TestPublicNodeLocalFullWithdrawConfirmationResetsWhenNodesReturn},
		{"active publish reads back VIP and assignment", TestPublicNodeLocalActivePublishReadsBackVIPAndAssignment},
		{"child spec drift repairs in place", TestPublicNodeLocalChildSpecDriftRepairsInPlace},
		{"missing child is recreated", TestPublicNodeLocalMissingChildIsRecreatedWithoutWithdraw},
		{"child repair restores every kept VIP", TestPublicNodeLocalChildRepairRestoresVIPsOfEveryKeptNode},
		{"stuck add does not starve gone removal", TestPublicNodeLocalStuckAddDoesNotStarveGoneRemoval},
		{"pool switch make before break", TestPublicNodeLocalPoolSwitchMakeBeforeBreak},
		{"pool change starts without touching the edge", TestPublicNodeLocalPoolChangeStartsTransitionWithoutTouchingTheEdge},
		{"pool switch refused when the target port is taken", TestPublicNodeLocalPoolSwitchRefusedWhenTargetPoolPortTaken},
		{"promotion requires the target converged", TestPublicNodeLocalPromotionRequiresTargetConverged},
		{"port add make before break", TestPublicNodeLocalPortAddMakeBeforeBreak},
		{"port removal closes firewall before VIP", TestPublicNodeLocalPortRemovalClosesFirewallBeforeVIP},
		{"source range change", TestPublicNodeLocalSourceRangeChangeKeepsServing},
		{"mixed policy change", TestPublicNodeLocalMixedPolicyChangeKeepsServing},
		{"revert prunes the target only", TestPublicNodeLocalTransitionRevertPrunesTargetOnly},
		{"policy change revert", TestPublicNodeLocalPolicyChangeRevertRestoresActiveFirewall},
		{"retarget", TestPublicNodeLocalTransitionRetargetAbortsThenStartsAgain},
		{"pool and policy together", TestPublicNodeLocalPoolAndPolicyChangeTogether},
		{"restart at every step", TestPublicNodeLocalTransitionResumesAfterRestartAtEveryStep},
		{"incremental sequences survive the Nth provider failure", TestPublicNodeLocalIncrementalSequencesSurviveNthProviderFailure},
		{"transitions survive the Nth provider failure", TestPublicNodeLocalTransitionSurvivesNthProviderFailure},
		{"pending transition keeps converging", TestPublicNodeLocalPendingTransitionKeepsConvergingUnderActiveIdentity},
		{"pending pool change still adds nodes", TestPublicNodeLocalPendingPoolChangeStillAddsNodesUnderActivePool},
		{"held policy recreates a missing child", TestPublicNodeLocalHeldPolicyRecreatesMissingChild},
		{"union recreates a missing child", TestPublicNodeLocalUnionRecreatesMissingChildWithOldPorts},
		{"union removes a node without an endpoint after grace", TestPublicNodeLocalUnionStillRemovesNodeWithoutEndpointAfterGrace},
		{"allow-rebuild withdraws and rebuilds", TestPublicNodeLocalAllowRebuildAnnotationPermitsWithdrawAndRebuild},
		{"keeps published state on transient errors", TestPublicNodeLocalKeepsPublishedStateOnTransientProviderErrors},
	}
}

func TestPublicNodeLocalScenariosOnBothFirewallModes(t *testing.T) {
	for _, mode := range []PublicNodeLocalFirewallMode{PublicNodeLocalFirewallModePerService, PublicNodeLocalFirewallModePerVM} {
		mode := mode
		for _, scenario := range publicNodeLocalModeScenarios() {
			scenario := scenario
			t.Run(string(mode)+"/"+scenario.name, func(t *testing.T) {
				previousMode, previousGated := publicNodeLocalTestMode, publicNodeLocalTestGated
				publicNodeLocalTestMode, publicNodeLocalTestGated = mode, true
				t.Cleanup(func() { publicNodeLocalTestMode, publicNodeLocalTestGated = previousMode, previousGated })
				scenario.run(t)
			})
		}
	}
}
