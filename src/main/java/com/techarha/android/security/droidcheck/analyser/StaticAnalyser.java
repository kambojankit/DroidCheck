package com.techarha.android.security.droidcheck.analyser;

import java.io.*;
import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by ankit on 19/05/15.
 */
public class StaticAnalyser {

    public void analysePermissions(String aaptPath, String staticResultPath, String apkFilePath){

        staticResultPath = staticResultPath+"static/";
        String command = "./aapt dump permissions %s";

        //prepare list of benign apks in directory
        Map<String, String> benignNameListMap = fetchApkNameList(apkFilePath+"benign/");

        //extracts permissions of benign apps
        extractPermissions(aaptPath, staticResultPath+"benign/", command, benignNameListMap);

        //prepare list of malicious apks in directory
        Map<String, String> maliciousNameListMap = fetchApkNameList(apkFilePath+"malicious/");

        //extracts permissions of malicious apps
        extractPermissions(aaptPath, staticResultPath+"malicious/", command, maliciousNameListMap);
    }

    private void extractPermissions(String aaptPath, String staticResultPath, String command, Map<String, String> benignNameListMap) {
        System.out.println("***********************************************************************");
        System.out.println("Started Extracting permissions.");
        System.out.println("***********************************************************************");
        for(Map.Entry<String, String> entry : benignNameListMap.entrySet()){
            BufferedWriter br = null;
            BufferedReader stdInput = null;
            try {

                String nCommand = String.format(command, entry.getValue());
                System.out.println("Extracting permissions for :"+entry.getKey());
                System.out.println("\t"+nCommand);

                Process proc = Runtime.getRuntime().exec(nCommand, null, new File(aaptPath));

                stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));

                final File parent = new File(staticResultPath);

                if(!parent.exists()){
                    parent.mkdirs();
                }

                final File outputFile = new File(parent,entry.getKey()+".txt");

                br = new BufferedWriter(new FileWriter(outputFile));
                String s = null;
                while ((s = stdInput.readLine()) != null) {
                    br.write(s+"\n");
                }
                System.out.println("\tExtracted permissions to: "+outputFile);
            } catch (IOException e) {
                e.printStackTrace();
            }finally {
                try {
                    if (br != null)br.close();
                    if (stdInput != null)stdInput.close();
                } catch (IOException ex) {
                    ex.printStackTrace();
                }
            }
        }
        System.out.println("---------- Extraction Completed Successfully -------------");
    }

    private Map<String, String> fetchApkNameList(String apkFilePath){
        String apkLoc = apkFilePath +"apks/";

        Map<String, String> apkNameList = new HashMap<String, String>();
        BufferedReader br = null;

        System.out.println("**************************************************************************");
        System.out.println("Started listing the files at location: "+ apkLoc);
        System.out.println("**************************************************************************");

        try {

            String sCurrentFileName;

            File curDir = new File(apkLoc);

            File[] filesList = curDir.listFiles();
            for(File f : filesList){
                if(f.isFile()){
                    sCurrentFileName = f.getName();
                    String output = "";
                    if(isAPK(sCurrentFileName)){
                        int length = sCurrentFileName.length();
                        output = sCurrentFileName.substring(0, (length - 4));
                    }else{
                        output = sCurrentFileName;
                    }
                    apkNameList.put(output, apkLoc + sCurrentFileName);

                    System.out.println(output + " added to listing");
                }
            }

        } catch (Exception e) {
            System.err.println("An Error occurred while preparing APK name list.");
        } finally {
            try {
                if (br != null)br.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }

        System.out.println("---------- Files Listed Successfully ---------------");
        return apkNameList;
    }

    private boolean isAPK(String name){
        return (name.endsWith(".apk")||name.endsWith(".APK"));
    }

}
