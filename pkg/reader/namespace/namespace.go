// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package namespace

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/tetragon/api/v1/tetragon"
	"github.com/cilium/tetragon/pkg/api/processapi"
	"github.com/cilium/tetragon/pkg/kernels"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

var (
	listNamespaces = [10]string{"uts", "ipc", "mnt", "pid", "pid_for_children", "net", "time", "time_for_children", "cgroup", "user"}
	// Host namespaces
	knownNamespaces = make(map[string]*tetragon.Namespace)
	hostNamespaces  *tetragon.Namespaces

	// If kernel supports time namespace
	TimeNsSupport bool
)

// GetPidNsInode() returns the inode of the target namespace pointed by pid.
// Returns:
//
//	namespace inode and nil on success
//	0 and error on failures.
func GetPidNsInode(pid uint32, nsStr string) (uint32, error) {
	pidStr := strconv.Itoa(int(pid))
	netns := filepath.Join(option.Config.ProcFS, pidStr, "ns", nsStr)
	netStr, err := os.Readlink(netns)
	if err != nil {
		return 0, fmt.Errorf("namespace '%s' %v", netns, err)
	}
	fields := strings.Split(netStr, ":")
	if len(fields) < 2 {
		return 0, fmt.Errorf("parsing namespace '%s' fields", netns)
	}
	inode := fields[1]
	inode = strings.TrimRight(inode, "]")
	inode = strings.TrimLeft(inode, "[")
	inodeEntry, _ := strconv.ParseUint(inode, 10, 32)
	return uint32(inodeEntry), nil
}

func GetMyPidG() uint32 {
	selfBinary := filepath.Base(os.Args[0])
	if procfs := os.Getenv("TETRAGON_PROCFS"); procfs != "" {
		procFS, _ := os.ReadDir(procfs)
		for _, d := range procFS {
			if d.IsDir() == false {
				continue
			}
			cmdline, err := os.ReadFile(filepath.Join(procfs, d.Name(), "/cmdline"))
			if err != nil {
				continue
			}
			if strings.Contains(string(cmdline), selfBinary) {
				pid, err := strconv.ParseUint(d.Name(), 10, 32)
				if err != nil {
					continue
				}
				return uint32(pid)
			}
		}
	}
	return uint32(os.Getpid())
}

func GetHostNsInode(nsStr string) (uint32, error) {
	return GetPidNsInode(1, nsStr)
}

func GetSelfNsInode(nsStr string) (uint32, error) {
	return GetPidNsInode(uint32(GetMyPidG()), nsStr)
}

func GetCurrentNamespace() *tetragon.Namespaces {
	_, err := InitHostNamespace()
	if err != nil {
		return nil
	}
	self_ns := make(map[string]uint32)
	for i := 0; i < len(listNamespaces); i++ {
		ino, err := GetSelfNsInode(listNamespaces[i])
		if err != nil {
			logger.GetLogger().WithError(err).Warnf("Failed to read current namespace")
			continue
		}
		self_ns[listNamespaces[i]] = ino
	}

	retVal := &tetragon.Namespaces{
		Uts: &tetragon.Namespace{
			Inum:   self_ns["uts"],
			IsHost: self_ns["uts"] == knownNamespaces["uts"].Inum,
		},
		Ipc: &tetragon.Namespace{
			Inum:   self_ns["ipc"],
			IsHost: self_ns["ipc"] == knownNamespaces["ipc"].Inum,
		},
		Mnt: &tetragon.Namespace{
			Inum:   self_ns["mnt"],
			IsHost: self_ns["mnt"] == knownNamespaces["mnt"].Inum,
		},
		Pid: &tetragon.Namespace{
			Inum:   self_ns["pid"],
			IsHost: self_ns["pid"] == knownNamespaces["pid"].Inum,
		},
		PidForChildren: &tetragon.Namespace{
			Inum:   self_ns["pid_for_children"],
			IsHost: self_ns["pid_for_children"] == knownNamespaces["pid_for_children"].Inum,
		},
		Net: &tetragon.Namespace{
			Inum:   self_ns["net"],
			IsHost: self_ns["net"] == knownNamespaces["net"].Inum,
		},
		Time: &tetragon.Namespace{
			Inum: self_ns["time"],
			// this kernel does not support time namespace
			IsHost: knownNamespaces["time"].Inum != 0 && self_ns["time"] == knownNamespaces["time"].Inum,
		},
		TimeForChildren: &tetragon.Namespace{
			Inum: self_ns["time_for_children"],
			// this kernel does not support time namespace
			IsHost: knownNamespaces["time_for_children"].Inum != 0 && self_ns["time_for_children"] == knownNamespaces["time_for_children"].Inum,
		},
		Cgroup: &tetragon.Namespace{
			Inum:   self_ns["cgroup"],
			IsHost: self_ns["cgroup"] == knownNamespaces["cgroup"].Inum,
		},
		User: &tetragon.Namespace{
			Inum:   self_ns["user"],
			IsHost: self_ns["user"] == knownNamespaces["user"].Inum,
		},
	}

	// this kernel does not support time namespace
	if retVal.Time.Inum == 0 {
		retVal.Time = nil
		retVal.TimeForChildren = nil
	}

	return retVal
}

func GetMsgNamespaces(ns processapi.MsgNamespaces) (*tetragon.Namespaces, error) {
	hostNs, err := InitHostNamespace()
	if err != nil {
		return nil, err
	}
	retVal := &tetragon.Namespaces{
		Uts: &tetragon.Namespace{
			Inum:   ns.UtsInum,
			IsHost: hostNs.Uts.Inum == ns.UtsInum,
		},
		Ipc: &tetragon.Namespace{
			Inum:   ns.IpcInum,
			IsHost: hostNs.Ipc.Inum == ns.IpcInum,
		},
		Mnt: &tetragon.Namespace{
			Inum:   ns.MntInum,
			IsHost: hostNs.Mnt.Inum == ns.MntInum,
		},
		Pid: &tetragon.Namespace{
			Inum:   ns.PidInum,
			IsHost: hostNs.Pid.Inum == ns.PidInum,
		},
		PidForChildren: &tetragon.Namespace{
			Inum:   ns.PidChildInum,
			IsHost: hostNs.PidForChildren.Inum == ns.PidChildInum,
		},
		Net: &tetragon.Namespace{
			Inum:   ns.NetInum,
			IsHost: hostNs.Net.Inum == ns.NetInum,
		},
		Time: &tetragon.Namespace{
			Inum: ns.TimeInum,
			// this kernel does not support time namespace
			IsHost: hostNs.Time.Inum != 0 && hostNs.Time.Inum == ns.TimeInum,
		},
		TimeForChildren: &tetragon.Namespace{
			Inum: ns.TimeChildInum,
			// this kernel does not support time namespace
			IsHost: hostNs.TimeForChildren.Inum != 0 && hostNs.TimeForChildren.Inum == ns.TimeChildInum,
		},
		Cgroup: &tetragon.Namespace{
			Inum:   ns.CgroupInum,
			IsHost: hostNs.Cgroup.Inum == ns.CgroupInum,
		},
		User: &tetragon.Namespace{
			Inum:   ns.UserInum,
			IsHost: hostNs.User.Inum == ns.UserInum,
		},
	}

	// this kernel does not support time namespace
	if retVal.Time.Inum == 0 {
		retVal.Time = nil
		retVal.TimeForChildren = nil
	}

	return retVal, nil
}

func InitHostNamespace() (*tetragon.Namespaces, error) {
	if hostNamespaces != nil {
		return hostNamespaces, nil
	}

	kernelVer, _, _ := kernels.GetKernelVersion(option.Config.KernelVersion, option.Config.ProcFS)
	// time and time_for_children namespaces introduced in kernel 5.6
	TimeNsSupport = (int64(kernelVer) >= kernels.KernelStringToNumeric("5.6.0"))

	if TimeNsSupport == false {
		logger.GetLogger().Infof("Kernel version %s doesn't support time namespaces", kernelVer)
	}

	for _, n := range listNamespaces {
		ino, err := GetPidNsInode(1, n)
		if err != nil {
			// No support for time namespace
			if (n == "time" || n == "time_for_children") && TimeNsSupport == false {
				knownNamespaces[n] = &tetragon.Namespace{Inum: 0, IsHost: false}
				continue
			}
			return nil, err
		}
		knownNamespaces[n] = &tetragon.Namespace{
			Inum:   ino,
			IsHost: true,
		}
	}

	hostNamespaces = &tetragon.Namespaces{
		Uts:             knownNamespaces["uts"],
		Ipc:             knownNamespaces["ipc"],
		Mnt:             knownNamespaces["mnt"],
		Pid:             knownNamespaces["pid"],
		PidForChildren:  knownNamespaces["pid_for_children"],
		Net:             knownNamespaces["net"],
		Time:            knownNamespaces["time"],
		TimeForChildren: knownNamespaces["time_for_children"],
		Cgroup:          knownNamespaces["cgroup"],
		User:            knownNamespaces["user"],
	}
	return hostNamespaces, nil
}
