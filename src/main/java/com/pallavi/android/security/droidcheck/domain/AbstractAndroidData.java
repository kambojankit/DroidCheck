package com.pallavi.android.security.droidcheck.domain;

/**
 * Created by ankit on 06/06/15.
 */
public abstract class AbstractAndroidData {
    private AndroidSample androidSample;
    private String packageName;
    private String activityName;

    public AndroidSample getAndroidSample() {
        return androidSample;
    }

    public void setAndroidSample(AndroidSample androidSample) {
        this.androidSample = androidSample;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getActivityName() {
        return activityName;
    }

    public void setActivityName(String activityName) {
        this.activityName = activityName;
    }
}
