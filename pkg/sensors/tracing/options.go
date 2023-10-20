// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package tracing

import (
	"fmt"
	"strconv"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/option"
)

type opt struct {
	name string
	set  func(val string) error
}

type kprobeOptions struct {
	DisableKprobeMulti bool
}

func getKprobeOptions(specs []v1alpha1.OptionSpec) (*kprobeOptions, error) {
	options := &kprobeOptions{}

	// Allowed options
	var opts = []opt{
		opt{
			// local --disable-kprobe-multi
			name: option.KeyDisableKprobeMulti,
			set: func(str string) (err error) {
				options.DisableKprobeMulti, err = strconv.ParseBool(str)
				return err
			},
		},
	}

	// cross reference allowed with passed options
	for i := range specs {
		spec := specs[i]

		for j := range opts {
			opt := opts[j]

			if opt.name == spec.Name {
				if err := opt.set(spec.Value); err != nil {
					return nil, fmt.Errorf("failed to set option %s: %s", opt.name, err)
				}
				logger.GetLogger().Infof("Set option %s = %s", spec.Name, spec.Value)
			}
		}
	}

	return options, nil
}
