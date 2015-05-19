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

    public void analysePermissions(String aaptPath, String statisResultPath, String apkFilePath){

        String command = "./aapt dump permissions %s";

        Map<String, String> nameListMap = fetchApkNameList(apkFilePath);

        for(Map.Entry<String, String> entry : nameListMap.entrySet()){
            BufferedWriter br = null;
            BufferedReader stdInput = null;
            try {

                String nCommand = String.format(command, entry.getValue());
                System.out.println(nCommand);

                Process proc = Runtime.getRuntime().exec(nCommand, null, new File(aaptPath));

                stdInput = new BufferedReader(new InputStreamReader(proc.getInputStream()));
                br = new BufferedWriter(new FileWriter(statisResultPath+entry.getKey()+".txt"));
                String s = null;
                while ((s = stdInput.readLine()) != null) {
                    br.write(s+"\n");
                }

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
    }

    private Map<String, String> fetchApkNameList(String apkFilePath){
        String apkList = apkFilePath+"apkList.txt";
        String apkLoc = apkFilePath +"apks/";

        Map<String, String> apkNameList = new HashMap<String, String>();
        BufferedReader br = null;

        try {

            String sCurrentLine;

            br = new BufferedReader(new FileReader(apkList));

            while ((sCurrentLine = br.readLine()) != null) {
                int length = sCurrentLine.length();
                String output = sCurrentLine.substring(0, (length - 4));
                apkNameList.put(output, apkLoc + sCurrentLine);
            }

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }finally {
            try {
                if (br != null)br.close();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        }
        return apkNameList;
    }
}
