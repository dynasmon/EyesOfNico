package ui

import "runtime"

func processKeys() string {
	if runtime.GOOS == "windows" {
		return "Enter process details / x force termination / k,z unavailable"
	}
	return "Enter process details / k SIGTERM / x SIGKILL / z stop/resume"
}

func pauseKeys() string {
	if !supportsSuspend {
		return "p or Space pause / + faster / - slower / Ctrl-Z unavailable"
	}
	return "p or Space pause / + faster / - slower / Ctrl-Z suspend"
}
