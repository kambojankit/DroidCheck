package com.pallavi.android.security.droidcheck.domain;

/**
 * Created by ankit on 07/06/15.
 */
public class AndroidSample {
    private String name;
    private String fullName;
    private String pathToApk;
    private boolean isMalicious;

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPathToApk() {
        return pathToApk;
    }

    public void setPathToApk(String pathToApk) {
        this.pathToApk = pathToApk;
    }

    public boolean isMalicious() {
        return isMalicious;
    }

    public void setMalicious(boolean isMalicious) {
        this.isMalicious = isMalicious;
    }
}
