import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.spec.*;
import javax.crypto.*;

import java.net.*;
import java.util.*;

import java.io.*;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class OnionNode {
    private static int HEADER_LENGTH = 6; // 2 bytes for '#' and '!' and 4 bytes for the int of the next port

    private Map<Integer, SecretKey> receivePortKey = new HashMap<Integer, SecretKey>();
    private Map<Integer, Integer> destToSource = new HashMap<Integer, Integer>();

    private DatagramSocket socket;
    private PrivateKey privKey;
    private PublicKey pubKey;
    private int port;
    private InetAddress localhost = InetAddress.getByName("localhost");

    private byte[] data = new byte[1024];


    /* used by a source node */
    private SecretKey[] allSecretKeys;
    private PublicKey[] allPublicKeys;
    private int[] ports;
    private int pathLength;

    public OnionNode(int port, PublicKey pubKey, PrivateKey privKey, int pathLength) throws Exception {
        this.socket = new DatagramSocket(port);
        this.port = port;
        this.pubKey = pubKey;
        this.privKey = privKey;
        this.pathLength = pathLength;

        System.out.println("Created node with port " + port);
        //System.out.println(new String(privKey.getEncoded()));
    }

    public void start() throws Exception{
        // just a relay node
        if (pathLength == 0) {
            while (true) {
                DatagramPacket receivePacket = new DatagramPacket(data, data.length);
                socket.receive(receivePacket);

                if (receivePortKey.get(receivePacket.getPort()) != null) {
                    parseRelay(receivePacket);
                }
                /* sending information back from destination to source */
                else if (destToSource.get(receivePacket.getPort()) != null) {
                    sendToSource(receivePacket);
                }
                else {
                    System.out.println("Received request to establish connection.");
                    parseSetup(receivePacket);
                }
            }
        }
        else {
            getUserInput();
        }
    }

    /**
     * Decrypts a set up message and sends a reply confirmation
     */
    private void parseSetup(DatagramPacket receivePacket) throws Exception {
        /* decrypt the data */
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] decryptedData = cipher.doFinal(data, 0, receivePacket.getLength());
        System.out.println("setup packet contents (secret key): " + new String(decryptedData, 0, decryptedData.length, StandardCharsets.US_ASCII));

        /* store secret key */
        SecretKey secretKey = new SecretKeySpec(decryptedData, 0, decryptedData.length, "AES");
        receivePortKey.put(receivePacket.getPort(), secretKey);

        byte[] confirmation = {(byte) '!'};
        byte[] encryptedData = encryptSymmetric(confirmation, confirmation.length, secretKey);
        DatagramPacket sendPacket = new DatagramPacket(encryptedData, encryptedData.length, localhost, receivePacket.getPort()); 
        socket.send(sendPacket);

    }

    /**
     * Decrypts a relay message and sends it to the next node
     */
    private void parseRelay(DatagramPacket receivePacket) throws Exception {
        SecretKey secKey = receivePortKey.get(receivePacket.getPort());
        byte[] decryptedData = decryptSymmetric(data, receivePacket.getLength(), secKey);

        if (decryptedData[0] == (byte) '#' && decryptedData[1] == (byte) '!') {
            // Get the 4 byte int starting at position 2
            int nextPort = ByteBuffer.wrap(decryptedData).getInt(2);

            /* map the destination of the forwarded packet to the source of the original packet*/
            if (destToSource.get(nextPort) == null) {
                destToSource.put(nextPort, receivePacket.getPort());
            }
            DatagramPacket sendPacket = new DatagramPacket(decryptedData, HEADER_LENGTH, decryptedData.length - HEADER_LENGTH, localhost, nextPort);
            System.out.println("Received message at port " + port);
            System.out.println("Sending message to port " + nextPort);
            socket.send(sendPacket);
        }
        /* means we have to tear down connection */
        else if (decryptedData[0] == (byte) '#' && decryptedData[1] == (byte) '#') {
            // Get the 4 byte int starting at position 2
            int nextPort = ByteBuffer.wrap(decryptedData).getInt(2);

            /* removing memory of this connection */
            destToSource.remove(nextPort);
            receivePortKey.remove(receivePacket.getPort());

            DatagramPacket sendPacket = new DatagramPacket(decryptedData, HEADER_LENGTH, decryptedData.length - HEADER_LENGTH, localhost, nextPort);
            System.out.println("TORE DOWN CONNECTION");
            System.out.println("Received message at port " + port);
            System.out.println("Sending message to port " + nextPort);
            socket.send(sendPacket);
        }
        /* means that this is the endpoint of the onion network */
        else {
            if (decryptedData.length == 1 && decryptedData[0] == (byte) '.') {
                System.out.println("CONNECTION ENDED.");
                receivePortKey.remove(receivePacket.getPort());
            }
            System.out.print("RECEIVED MESSAGE: ");
            System.out.println(new String(decryptedData, 0, decryptedData.length, StandardCharsets.US_ASCII));
        }

    }

    /**
     * Encrypts a message from the destination to the source and sends it
     * Used in set up
     */
    private void sendToSource(DatagramPacket receivePacket) throws Exception {
        // get port number of the original source
        int sourcePort = destToSource.get(receivePacket.getPort()); 
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, receivePortKey.get(sourcePort));

        byte[] encryptedData = cipher.doFinal(data, 0, receivePacket.getLength());
        System.out.println("Returning packet to source...");

        DatagramPacket sendPacket = new DatagramPacket(encryptedData, encryptedData.length, localhost, sourcePort);
        socket.send(sendPacket);
    }

    /**
     * Utility function  to decrypt data
     */
    private byte[] decryptSymmetric(byte[] encryptedData, int length, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        byte[] decryptedData = cipher.doFinal(encryptedData, 0, length);

        return decryptedData;
    }

    /**
     * Utility function to encrypt data
     */
    private byte[] encryptSymmetric(byte[] rawData, int length, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedData = cipher.doFinal(rawData, 0, length);

        return encryptedData;
    }



    private void getUserInput() throws Exception {
        System.out.print("Getting public keys and finding a path...");
        getKeys();
        System.out.println("done.");
        System.out.println("Setting up connection...");
        setupConnection();
        System.out.println("Setting up connection...done");

        System.out.println("Please enter a message. Press enter when you are finished.");
        System.out.println("If you want to destroy a connection and set up a new one, enter a '.' (excluding the quotes) on its own line");
        System.out.println("If you want to destroy a connection and end this program, enter <CTRL+D> on its own line");
        while (true) {
            System.out.print("Message: ");
            BufferedReader fromUser = new BufferedReader(new InputStreamReader(System.in));
            String message = fromUser.readLine();

            // end of transmission
            if (message == null) {
                System.out.print("Tearing down connection. Please wait...");
                byte[] messageBytes = teardownConnection();
                DatagramPacket sendPacket = new DatagramPacket(messageBytes, messageBytes.length, localhost, ports[0]);
                socket.send(sendPacket);

                System.out.println("done.");
                break;
            }
            byte[] messageBytes = message.getBytes(StandardCharsets.US_ASCII);

            if (messageBytes.length == 1 && messageBytes[0] == (byte) '.') {
                System.out.print("Tearing down connection. Please wait...");
                messageBytes = teardownConnection();
                DatagramPacket sendPacket = new DatagramPacket(messageBytes, messageBytes.length, localhost, ports[0]);
                socket.send(sendPacket);

                System.out.println("done.");

                System.out.print("Getting public keys and finding a path...");
                getKeys();
                System.out.println("done.");
                System.out.print("Setting up connection...");
                setupConnection();
                System.out.println("done.");

            }
            else {
                System.out.println("Encrypting message. Please wait...");

                messageBytes = encryptMessage(messageBytes);


                System.out.println("Encryption done.");
                DatagramPacket sendPacket = new DatagramPacket(messageBytes, messageBytes.length, localhost, ports[0]);
                socket.send(sendPacket);

                System.out.println("Sent your message.");
            }
        }
    }

    private byte[] encryptMessage(byte[] message) throws Exception {
        byte[] messageBytes = Arrays.copyOf(message, message.length);
        // encrypt message
        for (int i = pathLength - 1; i >= 0; i--) {
            ByteBuffer bb;
            if (i != pathLength - 1) {
                bb = ByteBuffer.allocate(messageBytes.length + HEADER_LENGTH);
                bb.put((byte) '#');
                bb.put((byte) '!');
                bb.putInt(ports[i+1]);
            }
            else {
                /* this is the raw message for the final destination*/
                bb = ByteBuffer.allocate(messageBytes.length);
            }
            bb.put(messageBytes);
            bb.flip();

            messageBytes = new byte[bb.limit()];
            bb.get(messageBytes);

            messageBytes = encryptSymmetric(messageBytes, messageBytes.length, allSecretKeys[i]);
        }

        return messageBytes;
    }

    private byte[] teardownConnection() throws Exception {
        byte[] messageBytes = {(byte) '.'};
        // encrypt message
        for (int i = pathLength - 1; i >= 0; i--) {
            ByteBuffer bb;
            if (i != pathLength - 1) {
                bb = ByteBuffer.allocate(messageBytes.length + HEADER_LENGTH);
                bb.put((byte) '#');
                bb.put((byte) '#');
                bb.putInt(ports[i+1]);
            }
            else {
                bb = ByteBuffer.allocate(messageBytes.length);
            }
            bb.put(messageBytes);
            bb.flip();

            messageBytes = new byte[bb.limit()];
            bb.get(messageBytes);

            messageBytes = encryptSymmetric(messageBytes, messageBytes.length, allSecretKeys[i]);
        }

        return messageBytes;
    }

    private void getKeys() throws Exception {
        File keyDir = new File("public_keys/");
        File[] keyFiles = keyDir.listFiles();

        if (keyFiles.length < pathLength) {
            System.out.println("Not enough nodes");
            System.exit(1);
        }
        // make it random
        shuffleFiles(keyFiles);

        allSecretKeys = new SecretKey[pathLength];
        allPublicKeys = new PublicKey[pathLength];

        ports = new int[pathLength];
        int nextPort = 0;
        for (int i = 0; i < pathLength; i++) {
            File keyFile = keyFiles[i];
            nextPort = Integer.parseInt(keyFile.getName());
            ports[i] = nextPort;

            if (nextPort == this.port)
                continue;

            /* get public keys */
            FileInputStream fis = new FileInputStream(keyFile.getPath());
            byte[] encodedPublicKey = new byte[(int)keyFile.length()];
            fis.read(encodedPublicKey);
            fis.close();

            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
            allPublicKeys[i] = pubKey;

            /* generate secret keys */
            SecretKey secretKey = KeyGenerator.getInstance("AES").generateKey();
            allSecretKeys[i] = secretKey;
        }
    }

    private void shuffleFiles(File[] arr) throws Exception {
        Random rnd = new Random();
        for (int i = arr.length - 1; i >= 0; i--) {
            int index = rnd.nextInt(i+1);
            File a = arr[index];
            arr[index] = arr[i];
            arr[i] = a;
        }
    }

    private void setupConnection() throws Exception {
        for (int i = 0; i < pathLength; i++) {
            /* encrypt the secret key for node i*/
            byte[] secKeyBytes = allSecretKeys[i].getEncoded();
            PublicKey pubKey = allPublicKeys[i];
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);

            //System.out.println(messageBytes.length);
            byte[] encryptedData = cipher.doFinal(secKeyBytes);


            /* encrypt the message for all nodes before node i */
            for (int j = i - 1; j >= 0; j--) {
                ByteBuffer bb = ByteBuffer.allocate(encryptedData.length + HEADER_LENGTH);
                bb.put((byte) '#');
                bb.put((byte) '!');
                bb.putInt(ports[j+1]);
                bb.put(encryptedData);

                encryptedData = new byte[encryptedData.length + HEADER_LENGTH];
                bb.flip();

                bb.get(encryptedData);

                cipher = Cipher.getInstance("AES");
                cipher.init(Cipher.ENCRYPT_MODE, allSecretKeys[j]);

                encryptedData = cipher.doFinal(encryptedData);

            }
            DatagramPacket sendPacket = new DatagramPacket(encryptedData, encryptedData.length, localhost, ports[0]);
            socket.send(sendPacket);

            DatagramPacket receivePacket = new DatagramPacket(data, data.length);
            socket.receive(receivePacket);

            byte[] decryptedData = Arrays.copyOf(data, receivePacket.getLength());
            for (int j = 0; j <= i; j++) {
                decryptedData = decryptSymmetric(decryptedData, decryptedData.length, allSecretKeys[j]);
            }
            if (decryptedData.length == 1 && decryptedData[0] == (byte) '!') {
                System.out.println("Received ack from node " + ports[i]);
            }

        }
    }






    public static void main(String[] args) throws Exception {
        int port;
        int pathLength = 0;

        if (args.length == 1) {
            port = Integer.parseInt(args[0]);
        }
        else if (args.length == 3 && args[0].equals("-n")) {
            pathLength = Integer.parseInt(args[1]);
            port = Integer.parseInt(args[2]);
        }
        else {
            System.out.println("usage: java [options] OnionNode <port number>");
            System.out.println("options:\n\t-n <path length>:\t specifies that this is a source node and will construct a path with the specified length.");
            System.out.println("\t\t\tUser must guarantee that there are enough nodes for the path length. Otherwise, there will be unpredictable behavior.");
            return;
        }


        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        PublicKey pub = keyPair.getPublic();
        PrivateKey priv = keyPair.getPrivate();

        OnionNode node = new OnionNode(port, pub, priv, pathLength);

        byte[] pubBytes = pub.getEncoded();
        // File name is the port number
        if (pathLength == 0) {
            FileOutputStream keyFile = new FileOutputStream("public_keys/" + Integer.toString(port));
            keyFile.write(pubBytes);
            keyFile.close();
        }

        node.start();
    }
}


