package com.hotlink.loois.walletoom;

import android.Manifest;
import android.os.Environment;
import android.support.v4.app.ActivityCompat;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;
import android.view.View;

import org.web3j.crypto.CipherException;
import org.web3j.crypto.Credentials;
import org.web3j.crypto.WalletUtils;

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class MainActivity extends AppCompatActivity {

    private static final String TAG = "MainActivity";


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        ActivityCompat.requestPermissions(this, new String[] {Manifest.permission.WRITE_EXTERNAL_STORAGE}, 0);
    }

    public void onCreateFullWallet(View view) {
        String filePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/full";
        File file = new File(filePath);
        file.mkdirs();
        try {
            WalletUtils.generateFullNewWalletFile("a12345678", file);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CipherException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void onCreateLightWallet(View view) {
        String filePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/light";
        File file = new File(filePath);
        file.mkdirs();
        try {
            WalletUtils.generateLightNewWalletFile("a12345678", file);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        } catch (CipherException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

/*
    public void onImportWallet(View view) {
        try {
            //需提前将assets目录下的keystore.json文件推送到手机SD里面
            String filePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/keystore.json";
            File file = new File(filePath);
            Credentials credentials = WalletUtils.loadCredentials("a12345678", file);
            Log.d(TAG, "address:" + credentials.getAddress());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CipherException e) {
            e.printStackTrace();
        }
    }
*/

    public void onImportWallet(View view) {
        try {
            //需提前将assets目录下的keystore.json文件推送到手机SD里面
            String filePath = Environment.getExternalStorageDirectory().getAbsolutePath() + "/keystore.json";
            File file = new File(filePath);
            Credentials credentials = MyWalletUtils.loadCredentials("a12345678", file);
            Log.d(TAG, "address:" + credentials.getAddress());
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CipherException e) {
            e.printStackTrace();
        }
    }
}
