package com.pallavi.android.security.droidcheck.analyser;

import com.pallavi.android.security.droidcheck.domain.AndroidSample;
import com.pallavi.android.security.droidcheck.domain.StaticAndroidData;
import com.pallavi.android.security.droidcheck.utils.EnvironmentVariables;
import com.pallavi.android.security.droidcheck.utils.FileUtils;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by ankit on 19/05/15.
 */
public class StaticAnalyser {

    private String resultPath;
    private String command = "./aapt dump permissions %s";

    public Map<String, List<StaticAndroidData>> analyse(EnvironmentVariables env) {
        Map<String, List<StaticAndroidData>> map = new HashMap<String, List<StaticAndroidData>>();

        resultPath = env.getResultPath() + "static/";



        //Malicious
        List<AndroidSample> maliciousSamples = FileUtils.fetchMaliciousSamples(env);

        List<StaticAndroidData> maliciousAndroidDataList = extractSamplingData(env, maliciousSamples, true);

        removeAndMoveNullPackageSamples(maliciousAndroidDataList, env, true);

        map.put("malicious", maliciousAndroidDataList);

        printDataToFile(env, maliciousAndroidDataList, true);

        printDataToSingleFile(env, maliciousAndroidDataList, true);


        //benign
        List<AndroidSample> benignSamples = FileUtils.fetchBenignSamples(env);

        List<StaticAndroidData> benignAndroidDataList = extractSamplingData(env, benignSamples, false);

        removeAndMoveNullPackageSamples(benignAndroidDataList, env, false);

        map.put("benign", benignAndroidDataList);

        printDataToFile(env, benignAndroidDataList, false);

        printDataToSingleFile(env, benignAndroidDataList, false);

        return map;
    }

    private void removeAndMoveNullPackageSamples(List<StaticAndroidData> staticAndroidDataList, EnvironmentVariables env, boolean isMalicious) {
        List<StaticAndroidData> removedSamples = new ArrayList<StaticAndroidData>(0);
        for(StaticAndroidData sample : staticAndroidDataList){
            if(sample.getPackageName()==null || sample.getPermissions().size()==0){
                removedSamples.add(sample);
                BufferedWriter br;
                String resultData = env.getResultPath()+"/bad_files/apks/" + (isMalicious ? "malicious/" : "benign/");
                File resultPathTobadData = new File(resultData);
                if (!resultPathTobadData.exists()) {
                    resultPathTobadData.mkdirs();
                }
                try {
                    br = new BufferedWriter(new FileWriter(new File(sample.getAndroidSample().getPathToApk())));
                    String source = sample.getAndroidSample().getPathToApk();
                    String command = String.format("mv %s %s", source, resultData);
                    Process proc = Runtime.getRuntime().exec(command);

                } catch (IOException e) {
                    e.printStackTrace();
                }

            }
        }


        staticAndroidDataList.removeAll(removedSamples);
    }

    private void printDataToFile(EnvironmentVariables env, List<StaticAndroidData> androidDataList, boolean isMaliciousList) {
        BufferedWriter br = null, brt = null;

        String resPath = env.getResultPath() + "dynamic/datalist/" + (isMaliciousList ? "malicious/" : "benign/");

        final File parent = new File(resPath);

        if (!parent.exists()) {
            parent.mkdirs();
        }

        try {
            br = new BufferedWriter(new FileWriter(new File(parent, "packageList.txt")));
            brt = new BufferedWriter(new FileWriter(new File(parent, "launcherNames.txt")));
            for (StaticAndroidData data : androidDataList) {
                br.write(data.getPackageName() + "\n");
                brt.write(data.getActivityName() + "\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (br != null) br.close();
                if (brt != null) brt.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
//
    }

    private void printDataToSingleFile(EnvironmentVariables env, List<StaticAndroidData> androidDataList, boolean isMaliciousList) {
        BufferedWriter br = null;

        String resPath = env.getResultPath() + "WEKA/" + (isMaliciousList ? "malicious/" : "benign/");

//        isMaliciousList ? "malicious/" : "benign/"

        final File parent = new File(resPath);

        if (!parent.exists()) {
            parent.mkdirs();
        }

        try {
            br = new BufferedWriter(new FileWriter(new File(parent, "PERMISSION_LIST.csv")));
            String heading = new String("permission_count, Permission_name, isMalware") + "\n";
            br.write(heading);
            for (StaticAndroidData data : androidDataList) {
                String row = new String("");
                String permissions = "";
                int size = data.getPermissions().size();

                for(String perm : data.getPermissions()){
                    String[] permName = perm.split("\\.");
                    int arrLen = permName.length;
                    permissions = permissions + permName[arrLen-1]+",";
                }
                if(permissions.length()>1){
                    permissions ="\""+ permissions.substring(0,permissions.length()-1) +"\"";
                }

                String isMalware = isMaliciousList ? "yes" : "no";

                row = row + size + "," + permissions+"," + isMalware + "\n";

                br.write(row);
            }

        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                if (br != null) br.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
//
    }

    private List<StaticAndroidData> extractSamplingData(EnvironmentVariables env, List<AndroidSample> sampleList, boolean isMaliciousList) {
        List<StaticAndroidData> androidData = new ArrayList<StaticAndroidData>();

        BufferedWriter br = null;
        for (AndroidSample sample : sampleList) {

            StaticAndroidData staticAndroidData = new StaticAndroidData();
            staticAndroidData.setAndroidSample(sample);
            try {
                //executePackageCommand(env, staticAndroidData);
                //executePermissionsCommand(env, staticAndroidData);
                executeLaunchableCommand(env, staticAndroidData);

                if(staticAndroidData.getPackageName()==null || staticAndroidData.getPermissions().size()==0){
                    continue;
                }

                String resPath = env.getResultPath() + "static/" + (isMaliciousList ? "malicious/" : "benign/");

                final File parent = new File(resPath);

                if (!parent.exists()) {
                    parent.mkdirs();
                }

                final File outputFile = new File(parent, sample.getName() + ".txt");

                br = new BufferedWriter(new FileWriter(outputFile));
                br.write(staticAndroidData.getPackageName() + "\n");
                br.write(staticAndroidData.getActivityName() + "\n");
                br.write("permissionList:\n");
                for (String permission : staticAndroidData.getPermissions()) {
                    br.write(permission + "\n");
                }
                System.out.println("\tExtracted permissions to: " + outputFile);

            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    if (br != null) br.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
            androidData.add(staticAndroidData);
        }

        return androidData;
    }


    private void executeLaunchableCommand(EnvironmentVariables env, StaticAndroidData staticAndroidData) throws IOException {
        String extractPackageCommand = String.format("./aapt dump badging %s", staticAndroidData.getAndroidSample().getPathToApk());
        Process proc = Runtime.getRuntime().exec(extractPackageCommand, null, new File(env.getSdkBuildToolsFilePath()));
        BufferedReader stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
        String s = null;
        while ((s = stdInput.readLine()) != null) {
            //Package
            if (s.contains("package:")) {
                int versionCodeIndex;
                int startInd = "package: name=".length();
                String packageName = "";
                if (s.contains("versionCode")) {
                    versionCodeIndex = s.indexOf(" versionCode");
                    packageName = s.substring(startInd + 1, versionCodeIndex - 1);
                } else {
                    packageName = s.substring(startInd + 1);
                    packageName = packageName.substring(0, packageName.length() - 1);
                }

                staticAndroidData.setPackageName(packageName);
                System.out.println(packageName);
            }
            //Launcher
            if (s.contains("launchable-activity:")) {
                int labelIndex = s.indexOf("  label=");
                int startInd = "launchable-activity: name=".length();

                String launcherActivity = s.substring(startInd + 1, labelIndex - 1);
                staticAndroidData.setActivityName(launcherActivity);
                System.out.println(launcherActivity);
            }
            //Permission
            if (s.contains("uses-permission:")) {
                int startInd = "uses-permission:".length();

                String permissionName = s.substring(startInd + 1);
                permissionName = permissionName.substring(0, permissionName.length() - 1);
                staticAndroidData.getPermissions().add(permissionName);
                System.out.println(permissionName);
            }
        }
    }
}
