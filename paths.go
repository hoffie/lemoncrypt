package main

import "os/user"

func expandTilde(path string) string {
	if path[0:2] != "~/" {
		return path
	}
	usr, err := user.Current()
	if err != nil {
		logger.Warningf("failed to execute tilde expansion in path, using as-si. (path=%s: %s)", path, err)
		return path
	}
	dir := usr.HomeDir
	return dir + path[1:]
}
