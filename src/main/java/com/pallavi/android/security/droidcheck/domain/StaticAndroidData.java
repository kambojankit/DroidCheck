package com.pallavi.android.security.droidcheck.domain;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by ankit on 06/06/15.
 */
public class StaticAndroidData extends AbstractAndroidData {
    private List<String> permissions;

    public StaticAndroidData() {
        this.permissions = new ArrayList<String>();
    }

    public List<String> getPermissions() {
        return permissions;
    }
}
