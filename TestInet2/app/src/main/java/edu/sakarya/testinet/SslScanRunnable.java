package edu.sakarya.testinet;

import android.content.Context;
import android.util.Log;
import android.widget.ImageView;
import android.widget.TextView;

import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.DecimalFormat;

import android.os.Handler;

import javax.net.SocketFactory;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocket;

public class SslScanRunnable implements Runnable {


    Context context;
    Handler handler;
    TextView textView;
    ImageView imageView;
    TextView secureStatus;

    private static Object LOCK;


    DecimalFormat df2;

    private final String[] hosts;
    private final int port = 443;

    private final double percent;
    private final int hostsLength;

    double totalPercent = 0.00;

    SocketFactory socketFactory = HttpsURLConnection.getDefaultSSLSocketFactory();


    public SslScanRunnable(Context context, Handler handler, TextView textView, ImageView imageView, TextView secureStatus) {
        this.context = context;
        this.handler = handler;
        this.textView = textView;
        this.imageView = imageView;
        this.secureStatus = secureStatus;
        df2 = new DecimalFormat(".##");

        hosts = new String[]{"google.com", "yandex.com", "twitter.com", "facebook.com", "gmail.com", "eksisozluk.com", "bing.com", "thequardian.com"};

        hostsLength = hosts.length;
        percent = (double) 100 / (double) hostsLength;
    }

    @Override
    public void run() {

        if (LOCK == null) {
            LOCK = new Object();
        } else {
            return;
        }
        int i = 0;
        for (totalPercent = 0.00; i < hostsLength; i++) {
            try {
                if (totalPercent < 50.00) {
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            imageView.setImageResource(R.drawable.ssl);
                            secureStatus.setText("Not Safe!");
                        }
                    });
                } else {
                    handler.post(new Runnable() {
                        @Override
                        public void run() {
                            imageView.setImageResource(R.drawable.ssl_ok);
                            secureStatus.setText("Safe");
                        }
                    });
                }
                SSLSocket socket = (SSLSocket) socketFactory.createSocket(hosts[i], port);

                socket.startHandshake();

                Certificate[] certs = socket.getSession().getPeerCertificates();

                int certsLength = certs.length;
                double totalcertPercent = 0.00;
                for (Certificate cert : certs) {
                    if (cert instanceof X509Certificate)
                        try {
                            ((X509Certificate) cert).checkValidity();

                            totalcertPercent = (percent) / ((double) certsLength);
                            //totalcertPercent =percent*(1/certsLength);
                            final double finaltotalcertPercent = totalcertPercent;
                            handler.post(new Runnable() {

                                @Override
                                public void run() {
                                    totalPercent = totalPercent + finaltotalcertPercent;
                                    textView.setText(String.valueOf("%" + df2.format(totalPercent)));
                                }
                            });
                            Log.e("Activate", "Certificate is active for current date");
                        } catch (CertificateExpiredException cee) {
                            Log.e("Expired", "Certificate is expired");
                            handler.post(new Runnable() {
                                @Override
                                public void run() {
                                    textView.setText(String.valueOf("%" + df2.format(totalPercent)));
                                }
                            });
                        } catch (CertificateNotYetValidException e) {
                            Log.e("", "######");
                            Log.e("Error: ", e.getMessage());
                            handler.post(new Runnable() {
                                @Override
                                public void run() {
                                    textView.setText(String.valueOf("%" + df2.format(totalPercent)));
                                }
                            });
                        }
                }
            } catch (Exception e) {
                Log.e("", "######");
                Log.e("Error", e.getMessage());
                handler.post(new Runnable() {
                    @Override
                    public void run() {
                        textView.setText(String.valueOf("%" + df2.format(totalPercent)));
                    }
                });
            }

        }
        LOCK = null;
    }
}
