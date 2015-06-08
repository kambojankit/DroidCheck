package com.pallavi.android.security.droidcheck.utils;

import com.pallavi.android.security.droidcheck.domain.AndroidSample;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by ankit on 04/06/15.
 */
public class FileUtils {

    public static List<AndroidSample> fetchBenignSamples(EnvironmentVariables env) {
        return fetchSamples(env.getSampleAPKFilePath() + "benign/", false);
    }

    public static List<AndroidSample> fetchMaliciousSamples(EnvironmentVariables env) {
        return fetchSamples(env.getSampleAPKFilePath() + "malicious/", true);
    }

    private static List<AndroidSample> fetchSamples(String apkFilePath, boolean isMaliciousApkPath) {
        List<AndroidSample> samplesList = new ArrayList<AndroidSample>();
        String apkLoc = apkFilePath + "apks/";

        BufferedReader br = null;

        System.out.println("**************************************************************************");
        System.out.println("Started listing the files at location: " + apkLoc);
        System.out.println("**************************************************************************");

        try {
            String sCurrentFileName;
            File curDir = new File(apkLoc);
            File[] filesList = curDir.listFiles();

            for (File f : filesList) {
                if (f.isFile()) {
                    AndroidSample sample = new AndroidSample();

                    sCurrentFileName = f.getName();
                    String output = "";

                    if (isAPK(sCurrentFileName)) {
                        int length = sCurrentFileName.length();
                        output = sCurrentFileName.substring(0, (length - 4));
                    } else {
                        output = sCurrentFileName;
                    }

                    sample.setName(output);
                    sample.setFullName(sCurrentFileName);
                    sample.setPathToApk(apkLoc + sCurrentFileName);
                    sample.setMalicious(isMaliciousApkPath);

                    samplesList.add(sample);
                    System.out.println(output + " added to listing");
                }
            }

        } catch (Exception e) {
            System.err.println("An Error occurred while preparing APK name list.");
        } finally {
            try {
                if (br != null) br.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

        System.out.println("---------- Files Listed Successfully ---------------");
        return samplesList;
    }

    private static boolean isAPK(String name) {
        return (name.endsWith(".apk") || name.endsWith(".APK"));
    }
}
