// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package exec

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/cilium/tetragon/api/v1/tetragon"
	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	grpcexec "github.com/cilium/tetragon/pkg/grpc/exec"
	"github.com/cilium/tetragon/pkg/jsonchecker"

	"github.com/cilium/tetragon/pkg/logger"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/option"
	"github.com/cilium/tetragon/pkg/sensors/base"
	"github.com/cilium/tetragon/pkg/testutils"
	"github.com/cilium/tetragon/pkg/testutils/perfring"
	tus "github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExit(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testNop := testutils.RepoRootPath("contrib/tester-progs/nop")

	procChecker := ec.NewProcessChecker().
		WithBinary(sm.Full(testNop))

	execChecker := ec.NewProcessExecChecker("exec").WithProcess(procChecker)
	exitChecker := ec.NewProcessExitChecker("exit").WithProcess(procChecker)

	var checker *ec.UnorderedEventChecker

	checker = ec.NewUnorderedEventChecker(execChecker, exitChecker)

	if err := exec.Command(testNop).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

func TestExitLeader(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib)
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testExitLeader := testutils.RepoRootPath("contrib/tester-progs/exit-leader")

	var startTime, exitTime time.Time

	// The test executes 'exit-leader' benary which spawns a thread and
	// exits the leader immediately while the new thread continues to
	// run for 3 seconds and exits. We verify that we get exit event 3
	// seconds after the start.

	nextCheck := func(event ec.Event, l *logrus.Logger) (bool, error) {
		switch ev := event.(type) {
		case *tetragon.ProcessExec:
			if ev.Process.Binary == testExitLeader {
				startTime = ev.Process.StartTime.AsTime()
			}
			return false, nil
		case *tetragon.ProcessExit:
			if ev.Process.Binary == testExitLeader {
				exitTime = ev.Time.AsTime()
			}
			return false, nil
		}
		return false, nil
	}

	finalCheck := func(l *logrus.Logger) error {
		delta := exitTime.Sub(startTime)

		fmt.Printf("execTime %v\n", startTime)
		fmt.Printf("exitTime %v\n", exitTime)
		fmt.Printf("delta %v\n", delta)

		if delta < 5*time.Second {
			return fmt.Errorf("unexpected delta < 5 seconds")
		}
		return nil
	}

	checker := &ec.FnEventChecker{
		NextCheckFn:  nextCheck,
		FinalCheckFn: finalCheck,
	}

	if err := exec.Command(testExitLeader).Run(); err != nil {
		t.Fatalf("Failed to execute test binary: %s\n", err)
	}

	if err := jsonchecker.JsonTestCheck(t, checker); err != nil {
		t.Logf("error: %s", err)
		t.Fail()
	}
}

// TestExitZombie tests whether we properly handle the thread group leader exiting before the other threads.
// see: tester-progs/exit-tester.c for the program we use to test this.
//
// The program will:
//   - create a thread
//   - have the group leader return
//   - once this happens, the thread (which continues to run) will exec a /bin/echo command
//
// In our test we check that the parent of the /bin/echo command is the exit-tester program.
func TestExitZombie(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	t.Logf("starting observer")
	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("GetDefaultObserverWithFile error: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testBin := testutils.RepoRootPath("contrib/tester-progs/exit-tester")
	testCmd := exec.CommandContext(ctx, testBin)
	testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
	if err != nil {
		t.Fatal(err)
	}
	defer testPipes.Close()

	if err := testCmd.Start(); err != nil {
		t.Fatal(err)
	}

	logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
	logWG.Wait()

	if err := testCmd.Wait(); err != nil {
		t.Fatalf("command failed with %s. Context error: %v", err, ctx.Err())
	}

	exitTesterCheck := ec.NewProcessChecker().WithBinary(sm.Suffix("tester-progs/exit-tester"))
	echoCheck := ec.NewProcessChecker().WithBinary(sm.Full("/bin/sh")).WithArguments(sm.Contains("pizza is the best!"))
	checker := ec.NewUnorderedEventChecker(
		ec.NewProcessExecChecker("exitTester").WithProcess(exitTesterCheck),
		ec.NewProcessExecChecker("echo").WithProcess(echoCheck).WithParent(exitTesterCheck),
	)

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// TestExitCode tests whether we properly return the exit code of the process.
// see: tester-progs/exit-code.c for the program we use to test this.
//
// The program will:
//   - return a exit code
//
// In our test we check whether the observed exit code equals the real exit code.
func TestExitCode(t *testing.T) {
	var doneWG, readyWG sync.WaitGroup
	defer doneWG.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	obs, err := observertesthelper.GetDefaultObserver(t, ctx, tus.Conf().TetragonLib, observertesthelper.WithMyPid())
	if err != nil {
		t.Fatalf("Failed to run observer: %s", err)
	}
	observertesthelper.LoopEvents(ctx, t, &doneWG, &readyWG, obs)
	readyWG.Wait()

	testExitCodeBinary := testutils.RepoRootPath("contrib/tester-progs/exit-code")

	// Test different exit codes
	testCases := []int8{
		// Test some usual exit code
		0,   // Generic success code.
		1,   // Generic failure or unspecified error.
		42,  // Arbitrary value
		125, // If the error is with Docker daemon itself
		126, // If the contained command cannot be invoked

		// Test some -errno
		-30, // -EROFS(Read-only file system)
		-31, // -EMLINK(Too many links)
		-32, // -EPIPE(Broken pipe)
		-33, // -EDOM(Math argument out of domain of func)
		-34, // -ERANGE(Math result not representable)
	}

	checker := ec.NewUnorderedEventChecker()
	testerBinaryCheck := ec.NewProcessChecker().WithBinary(sm.Suffix("tester-progs/exit-code"))

	for _, testCaseCode := range testCases {
		// convert the code to an unsigned 8 bits integer (example: -30 -> 226)
		// since Linux will return an unsigned integer after execution
		expectedCode := uint8(testCaseCode)

		if err := exec.Command(testExitCodeBinary, fmt.Sprint(testCaseCode)).Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				if uint8(exitErr.ExitCode()) != expectedCode {
					t.Errorf("unexpected: wanted exit code %d, execution returned %d", expectedCode, exitErr.ExitCode())
				}
			} else {
				t.Fatalf("failed to execute the test binary %q with exit code %d", err, expectedCode)
			}
		}

		checker.AddChecks(
			ec.NewProcessExitChecker(fmt.Sprintf("exitCode%d", expectedCode)).WithProcess(testerBinaryCheck).WithStatus(uint32(expectedCode)),
		)
	}

	err = jsonchecker.JsonTestCheck(t, checker)
	assert.NoError(t, err)
}

// This test ensures that we get the exit event only once
func TestExitEventOnce(t *testing.T) {
	testutils.CaptureLog(t, logger.GetLogger().(*logrus.Logger))

	ctx, cancel := context.WithTimeout(context.Background(), tus.Conf().CmdWaitTime)
	defer cancel()

	option.Config.HubbleLib = tus.Conf().TetragonLib
	option.Config.Verbosity = 3

	tus.LoadSensor(t, base.GetInitialSensor())
	testManager := setupObserver(ctx, t)

	testManager.AddAndEnableSensors(ctx, t, loadedSensors)
	t.Cleanup(func() {
		testManager.DisableSensors(ctx, t, loadedSensors)
	})

	pid := 0
	exitCounter := 0
	pidTidMismatch := 0
	trigger := func() {
		testAllThreads := testutils.RepoRootPath("contrib/tester-progs/exit-all-threads")
		testCmd := exec.CommandContext(ctx, testAllThreads)
		testPipes, err := testutils.NewCmdBufferedPipes(testCmd)
		if err != nil {
			t.Fatal(err)
		}
		defer testPipes.Close()
		if err := testCmd.Start(); err != nil {
			t.Fatal(err)
		}
		pid = testCmd.Process.Pid
		logWG := testPipes.ParseAndLogCmdOutput(t, nil, nil)
		logWG.Wait()

		if err := testCmd.Wait(); err != nil {
			t.Fatalf("command '%s' failed with: %s. Context error: %v", testAllThreads, err, ctx.Err())
		}
	}

	events := perfring.RunTestEvents(t, ctx, trigger)
	for _, ev := range events {
		if event, ok := ev.(*grpcexec.MsgExitEventUnix); ok {
			if uint32(pid) == event.ProcessKey.Pid {
				exitCounter++
			}
			if event.ProcessKey.Pid != event.Info.Tid {
				pidTidMismatch++
			}
		}
	}

	require.Equalf(t, 1, exitCounter, "Error received more than one exit event")
	require.Zerof(t, pidTidMismatch, "Error Pid and Tid mismatch")
}
