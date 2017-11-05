/*--------------------------------------------------------
1. Name / Date: Yiming Wang / Oct 28, 2017


2. Java version used, if not the official version for the class:
	java version "1.8.0_131"
	Java(TM) SE Runtime Environment (build 1.8.0_131-b11)
	Java HotSpot(TM) 64-Bit Server VM (build 25.131-b11, mixed mode)


3. Precise command-line compilation examples / instructions:
> 	javac Blockchain.java


4. Precise examples / instructions to run this program:
>	java Blockchain 0
>	java Blockchain 1
>	java Blockchain 2


5. List of files needed for running the program.
 		a. Blockchain.java
 		b. BlockInput0.txt
 		c. BlockInput1.txt
 		d. BlockInput2.txt


6. Notes:
	Sometimes when a process has finished the job, the rest of processes might need couple more seconds to finish and return the block chain.
	
	Very seldomly, process might be stuck (like every 30 times of testing?). If it does happen, please hit enter several times or re-test the 
	3 processes again. Sorry for the inconvenience. I guess it is possible due the thread issue? but I do set all of the functions called by 
	threads synchronized.
----------------------------------------------------------*/


import java.io.*;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Random;
import java.util.UUID;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;
import javax.xml.bind.Unmarshaller;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;

//import libraries

class WorkerF extends Thread { // the object to handle client sockets, which support multi-threads
	Socket sock; // create new socket which would be used to communicate with client

	WorkerF(Socket s) {// constructor. To initialize sock value.
		sock = s;
	}

	public synchronized void run() {
		// over-ride run() function in Thread. this function would run, after a thread start.
		// this function is to read the stream from client socket, then send back jokes/proverbs by mode.

		PrintStream out = null;
		BufferedReader in = null;

		try {
			in = new BufferedReader(new InputStreamReader(sock.getInputStream())); // read the stream from socket (a BufferedReader).
			out = new PrintStream(sock.getOutputStream()); // write stream to the socket (a PrintStream).
			try {
				String content = "";// to save all contents from stream
				String c = "";// temp place to save one line of stream content
				c = in.readLine();
				while (c != "" && c != null && in != null) {
					content = content + c + "\n";
					c = in.readLine();
				}
				checkAndSendKey(content);// check if public keep has been send out, if not, send to another 2 processes.
				Thread.sleep(100);
				String blockchainString = "";
				if (Blockchain.getLocalBlocksRead() == false) {//check if local block records in txt file has been read in.
					while (true) {
						if (Blockchain.allKeyReady()) {//check if all keys are read
							blockchainString = Blockchain.readBlockFile();// read in the block records in txt file.
							break;
						}
					}
					//send the block records xml to another processes.
					Blockchain.sendToOtherProcesses(blockchainString, "localhost", Blockchain.getId(), "un");
				}
				//check if the blocks already exist in the queue, if not, add it.
				checkAndAddBlocks(content);

			} catch (IOException x) { // catch IO exception, then continue.
				System.out.println("Server read error");
				x.printStackTrace(); // print out where does the error come from. i.e. which line(s)
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
			sock.close(); // close this socket
		} catch (IOException ioe) { // catch IO exception, then continue.
			System.out.println(ioe); // print out the exception
		}
	}


	public synchronized void checkAndAddBlocks(String combineText) {
		//this function is to check if a string is xml, if yes, convert it to list of Block records and add it to the queue (Blockchain.blocks) 
		if (combineText.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")) {
			//convert a xml string to a arraylist containing blockrecords. 
			JAXBContext jaxbContext;
			BlockRecords blockrecords = null;
			try {
				jaxbContext = JAXBContext.newInstance(BlockRecords.class); 
				Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
				blockrecords = (BlockRecords) jaxbUnmarshaller
						.unmarshal(new ByteArrayInputStream(combineText.getBytes()));
			} catch (JAXBException e) {
				e.printStackTrace();
			}

			//use a flag to check if a block record is alread in the arraylist.
			Boolean inList = false; 
			ArrayList<BlockRecord> tempList = new ArrayList<BlockRecord>();
			for (BlockRecord br : blockrecords.getBlockRecord()) {
				for (BlockRecord br2 : Blockchain.getBlocks()) {
					if (br.getABlockID().equals(br2.getABlockID())) {
						inList = true;
					}
				}
				if (!inList) {
					tempList.add(br);
				}
				inList = false;
			}
			//if the block record is not in Blockchain.Blocks, add the block to temp arraylist
			Blockchain.blocksAddAll(tempList);//add the arraylist to Blockchain.Blocks
		}
	}

	public synchronized void checkAndSendKey(String key) {
		//clean the key string, delete the new line sign. then, depending on the begining characters of the string, 
		//convert the string to public/private key by id, save it.
		String cleanKey = key.replace("\r\n", "").replace("\n", "");
		if (Blockchain.getId() != 2 && Blockchain.getPublicKey2() == null && key.contains("<p2 public key>")) {
			Blockchain.setPublicKey2(convertStringToKey(cleanKey.substring(15)));
			Blockchain.sendPublicKey(Blockchain.getId());
		} else {
			if (Blockchain.getId() != 0 && Blockchain.getPublicKey0() == null && key.contains("<p0 public key>")) {
				Blockchain.setPublicKey0(convertStringToKey(cleanKey.substring(15)));
			}
			if (Blockchain.getId() != 1 && Blockchain.getPublicKey1() == null && key.contains("<p1 public key>")) {
				Blockchain.setPublicKey1(convertStringToKey(cleanKey.substring(15)));
			}
		}
	}

	public PublicKey convertStringToKey(String keyString) {
		//convert the string to public/private key, return it.
		byte[] keyBytes = Base64.getMimeDecoder().decode(keyString);
		KeyFactory kf;
		PublicKey publicKey = null;
		try {
			kf = KeyFactory.getInstance("RSA");
			publicKey = kf.generatePublic(new X509EncodedKeySpec(keyBytes));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		return publicKey;
	}
}

class WorkerS extends Thread { // the object to handle client sockets, which support multi-threads
	Socket sock; // create new socket which would be used to communicate with client

	WorkerS(Socket s) { // constructor. To initialize sock value.
		sock = s;
	}

	public synchronized void run() {
		// over-ride run() function in Thread. this function would run, after a thread start.
		// this function is to read the stream from client socket, then send back jokes/proverbs by mode.

		PrintStream out = null;
		BufferedReader in = null;

		try {
			in = new BufferedReader(new InputStreamReader(sock.getInputStream())); // read the stream from socket (a BufferedReader).
			out = new PrintStream(sock.getOutputStream()); // write stream to the socket (a PrintStream).
			try {
				String content = "";
				String c = "";
				c = in.readLine();
				while (c != "" && c != null && in != null) {
					content = content + c + "\n";
					c = in.readLine();
				}
				//read in and combine all the content, call toTempchain(), if the content is a xml, would be assigned to Blockchain.tempBlockchain
				toTempchain(content);
			} catch (IOException x) { // catch IO exception, then continue.
				System.out.println("Server read error");
				x.printStackTrace(); // print out where does the error come from. i.e. which line(s)
			}
			sock.close(); // close this socket
		} catch (IOException ioe) { // catch IO exception, then continue.
			System.out.println(ioe); // print out the exception
		}
	}

	public synchronized void toTempchain(String combineText) {
		//if the input content is a xml, would be assigned to Blockchain.tempBlockchain
		if (combineText.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")) {
			JAXBContext jaxbContext;
			BlockRecords blockrecords = null;
			try {
				jaxbContext = JAXBContext.newInstance(BlockRecords.class);
				Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
				//convert to BlockRecords object, it contains a arraylist of blockrecord object
				blockrecords = (BlockRecords) jaxbUnmarshaller.unmarshal(new ByteArrayInputStream(combineText.getBytes()));
			} catch (JAXBException e) {
				e.printStackTrace();
			}
			//set Tempblockchain as arraylist of blockrecord from BlockRecords object
			Blockchain.setTempblockchain(blockrecords.getBlockRecord()); 
		}
	}
}

public class Blockchain {
	// blockchain class contains most of the fields we need in the application.
	private static int id;
	private static boolean localBlocksRead = false; // a flag to check if the local block txt file has been read in

	private static PublicKey publicKey0 = null;
	private static PublicKey publicKey1 = null;
	private static PublicKey publicKey2 = null;
	private static PrivateKey privateKey0 = null;
	private static PrivateKey privateKey1 = null;
	private static PrivateKey privateKey2 = null;

	static String serverName = "localhost";

	private static Queue<BlockRecord> blocks = new LinkedList<BlockRecord>();
	private static ArrayList<BlockRecord> blockchain = new ArrayList<BlockRecord>();
	private static ArrayList<BlockRecord> tempblockchain = new ArrayList<BlockRecord>();

	public static void main(String a[]) throws IOException {

		int q_len = 6; // Number of requests to handle
		// hard code all the port value
		final int port0_unverfied = 4710;
		final int port1_unverfied = 4711;
		final int port2_unverfied = 4712;
		final int port0_updated = 4820;
		final int port1_updated = 4821;
		final int port2_updated = 4822;

		int port_unverified;
		int port_updated;

		if (a.length < 1) {
			System.out.print("You should start the process by assigning process number as argument!");
			System.out.flush();
			System.exit(0);
		} else {
			// if legally arguments entered i.e. 0,1 or 2, start the process. otherwise, leave.
			//set the process id by argument, then start the 2 server port by calling preparePorts()
			// start updating by calling startUpdate(), start working on puzzles by calling workOnPuzzle();
			if (a[0].equals("0")) {
				port_unverified = port0_unverfied;
				port_updated = port0_updated;
				id = Integer.parseInt(a[0]);

				preparePorts(port_updated, port_unverified, q_len);
				startUpdate();
				workOnPuzzle();

			} else if (a[0].equals("1")) {
				port_unverified = port1_unverfied;
				port_updated = port1_updated;
				id = Integer.parseInt(a[0]);

				preparePorts(port_updated, port_unverified, q_len);
				startUpdate();
				workOnPuzzle();

			} else if (a[0].equals("2")) {
				// if the process has id equals 2, send out the public key the the rest of the 2 processes.
				port_unverified = port2_unverfied;
				port_updated = port2_updated;
				id = Integer.parseInt(a[0]);

				sendPublicKey(id);
				preparePorts(port_updated, port_unverified, q_len);
				startUpdate();
				workOnPuzzle();
			} else { // if the argument is invalid, print message and leave.
				System.out.println("Wrong argument! It should be 0, 1 or 2!");
				System.out.flush();
				System.exit(0);
			}
		}
	}

	// thread save setter and getter for the flag to detect whether local txt file has been read in.
	public synchronized static boolean getLocalBlocksRead() {
		return localBlocksRead;
	}

	public synchronized static void setLocalBlocksRead(boolean localBlocksRead) {
		Blockchain.localBlocksRead = localBlocksRead;
	}

	public static void preparePorts(int port_updated, int port_unverified, int q_len) {
		// start the 2 server port to handling blockchain updating and key/unverified blocks recieving.
		SecondaryPort sp = new SecondaryPort(port_updated, id); 
		Thread t_sp = new Thread(sp);
		t_sp.start(); // start it, waiting for new client

		FirstPort fp = new FirstPort(port_unverified, id);
		Thread t_fp = new Thread(fp);
		t_fp.start(); // start it, waiting for new client
	}

	public static void startUpdate() {
		Update sp = new Update(); // create a new thread to do the block updating
		Thread t_sp = new Thread(sp);
		t_sp.start(); // start it, waiting for new client
	}

	public static void workOnPuzzle() {
		SolvePuzzle sp = new SolvePuzzle(); // create a new thread to solve puzzle.
		Thread t_sp = new Thread(sp);
		t_sp.start(); // start it, waiting for new client new SolvePuzzle();

	}


	static synchronized void sendToOtherProcesses(String content, String serverName, int id, String p) {
		// by entering the current process id, send out the content the the rest of the 2 processes.
		// the string p very is used to detect the port value. update ( 482x ) or unverified blocks (471x )
		if (id == 0) {
			if (p.equals("un")) {
				Client c1 = new Client(content, serverName, id, 4711);
				Thread t_c1 = new Thread(c1);
				t_c1.start();
				Client c2 = new Client(content, serverName, id, 4712);
				Thread t_c2 = new Thread(c2);
				t_c2.start();
			}
			if (p.equals("up")) {
				Client c1 = new Client(content, serverName, id, 4821);
				Thread t_c1 = new Thread(c1);
				t_c1.start();
				Client c2 = new Client(content, serverName, id, 4822);
				Thread t_c2 = new Thread(c2);
				t_c2.start();
			}
		} else if (id == 1) {
			if (p.equals("un")) {
				Client c0 = new Client(content, serverName, id, 4710);
				Thread t_c0 = new Thread(c0);
				t_c0.start();
				Client c2 = new Client(content, serverName, id, 4712);
				Thread t_c2 = new Thread(c2);
				t_c2.start();
			} else {
				Client c0 = new Client(content, serverName, id, 4820);
				Thread t_c0 = new Thread(c0);
				t_c0.start();
				Client c2 = new Client(content, serverName, id, 4822);
				Thread t_c2 = new Thread(c2);
				t_c2.start();
			}
		} else {
			if (p.equals("un")) {
				Client c1 = new Client(content, serverName, id, 4711);
				Thread t_c1 = new Thread(c1);
				t_c1.start();
				Client c0 = new Client(content, serverName, id, 4710);
				Thread t_c0 = new Thread(c0);
				t_c0.start();
			} else {
				Client c1 = new Client(content, serverName, id, 4821);
				Thread t_c1 = new Thread(c1);
				t_c1.start();
				Client c0 = new Client(content, serverName, id, 4820);
				Thread t_c0 = new Thread(c0);
				t_c0.start();
			}
		}
	}

	static synchronized void sendToProcess(String content, String serverName, int id, String p) {
		// by entering the target process id and type ("up" for update, "un" for unverified blocks), send out the content
		if (id == 0) {
			if (p.equals("un")) {
				Client c1 = new Client(content, serverName, id, 4710);
				Thread t_c1 = new Thread(c1);
				t_c1.start();
			}
			if (p.equals("up")) {
				Client c1 = new Client(content, serverName, id, 4820);
				Thread t_c1 = new Thread(c1);
				t_c1.start();
			}
		}
		if (id == 1) {
			if (p.equals("un")) {
				Client c0 = new Client(content, serverName, id, 4711);
				Thread t_c0 = new Thread(c0);
				t_c0.start();
			} else {
				Client c0 = new Client(content, serverName, id, 4821);
				Thread t_c0 = new Thread(c0);
				t_c0.start();
			}
		}
		if (id == 2) {
			if (p.equals("un")) {
				Client c1 = new Client(content, serverName, id, 4712);
				Thread t_c1 = new Thread(c1);
				t_c1.start();
			} else {
				Client c1 = new Client(content, serverName, id, 4822);
				Thread t_c1 = new Thread(c1);
				t_c1.start();
			}
		}
	}

	public static KeyPair generateKeyPair(long seed) throws Exception {
		// generate public and private key pairs. the seed it the process id.
		KeyPairGenerator keyGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom rng = SecureRandom.getInstance("SHA1PRNG", "SUN");
		rng.setSeed(seed);
		keyGenerator.initialize(1024, rng);
		return (keyGenerator.generateKeyPair());
	}

	public static void sendPublicKey(int id) {
		// by inputing the process id, send the public key to another 2 processes.
		if (Blockchain.getBlockchain().isEmpty()) {
			Blockchain.blockchainAdd(new BlockRecord("dummy"));
		}
		if (id == 2) {
			String pKeyS2 = null;
			try {
				KeyPair keyPair = generateKeyPair(id);
				setPublicKey2(keyPair.getPublic());
				setPrivateKey2(keyPair.getPrivate());
				pKeyS2 = Base64.getMimeEncoder().encodeToString(publicKey2.getEncoded());
			} catch (Exception e) {
				e.printStackTrace();
			}
			pKeyS2 = "<p2 public key>" + pKeyS2;
			sendToOtherProcesses(pKeyS2, serverName, id, "un");
		}
		if (id == 0) {
			String pKeyS0 = null;
			try {
				KeyPair keyPair = generateKeyPair(id);
				setPublicKey0(keyPair.getPublic());
				setPrivateKey0(keyPair.getPrivate());

				pKeyS0 = Base64.getMimeEncoder().encodeToString(publicKey0.getEncoded());
			} catch (Exception e) {
				e.printStackTrace();
			}
			pKeyS0 = "<p0 public key>" + pKeyS0;
			sendToOtherProcesses(pKeyS0, serverName, id, "un");
		}
		if (id == 1) {
			String pKeyS1 = null;
			try {
				KeyPair keyPair = generateKeyPair(id);
				setPublicKey1(keyPair.getPublic());
				setPrivateKey1(keyPair.getPrivate());

				pKeyS1 = Base64.getMimeEncoder().encodeToString(publicKey1.getEncoded());
			} catch (Exception e) {
				e.printStackTrace();
			}
			pKeyS1 = "<p1 public key>" + pKeyS1;
			sendToOtherProcesses(pKeyS1, serverName, id, "un");
		}

	}

	public synchronized static String readBlockFile() {
		// function to read the block records in txt file.
		String FILENAME;
		final int iFNAME = 0;
		final int iLNAME = 1;
		final int iDOB = 2;
		final int iSSNUM = 3;
		final int iDIAG = 4;
		final int iTREAT = 5;
		final int iRX = 6;

		//set file name by the process id.
		switch (Blockchain.id) {
		case 1:
			FILENAME = "BlockInput1.txt";
			break;
		case 2:
			FILENAME = "BlockInput2.txt";
			break;
		default:
			FILENAME = "BlockInput0.txt";
			break;
		}
		try {
			try (BufferedReader br = new BufferedReader(new FileReader(FILENAME))) {
				String[] tokens = new String[10];
				String stringXML;
				String InputLineStr;
				String suuid;
				UUID idA;

				BlockRecord[] blockArray = new BlockRecord[20];

				JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
				Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
				StringWriter sw = new StringWriter();

				jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

				int n = 0;

				while ((InputLineStr = br.readLine()) != null) {
					//when in put string is not null, set up all the field value of each one of the blockrecord object in the array.
					blockArray[n] = new BlockRecord();
					idA = UUID.randomUUID();
					suuid = new String(UUID.randomUUID().toString());
					String sysTime = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date());
					blockArray[n].setABlockID(suuid);
					blockArray[n].setBSignedBlockID(Base64.getEncoder().encodeToString(SolvePuzzle.signData(suuid.getBytes(), choosePrivateKey(Blockchain.getId()))));
					blockArray[n].setACreatingProcess(Integer.toString(Blockchain.getId()));
					
					tokens = InputLineStr.split(" +"); // Tokenize the input
					blockArray[n].setFSSNum(tokens[iSSNUM]);
					blockArray[n].setFFname(tokens[iFNAME]);
					blockArray[n].setFLname(tokens[iLNAME]);
					blockArray[n].setFDOB(tokens[iDOB]);
					blockArray[n].setGDiag(tokens[iDIAG]);
					blockArray[n].setGTreat(tokens[iTREAT]);
					blockArray[n].setGRx(tokens[iRX]);
					blockArray[n].setCCreatedTime(sysTime);
					n++;
				}

				
				if (Blockchain.getLocalBlocksRead() == false) {
					// if the flag is off, turn it on, then, create a temp array to save the block record object read and converted from txt file
					// add the temp arraylist to the block queue.
					Blockchain.setLocalBlocksRead(true);
					ArrayList<BlockRecord> bl = new ArrayList<BlockRecord>();

					for (int i = 0; i < blockArray.length; i++) {
						if (blockArray[i] != null) {
							bl.add(blockArray[i]);
						}
					}
					Blockchain.blocksAddAll(bl);
				}

				stringXML = sw.toString();
				for (int i = 0; i < n; i++) {
					// put all the block record object information into the xml string.
					jaxbMarshaller.marshal(blockArray[i], sw);
				}
				// prepare the xml string by adding the <BlockLedger> and </BlockLedger>
				String fullBlock = sw.toString();
				String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
				String cleanBlock = fullBlock.replace(XMLHeader, "");
				String XMLBlock = XMLHeader + "\n<BlockLedger>" + cleanBlock + "</BlockLedger>";
				return XMLBlock;
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static long convertDateToLong(String d) {
		// convert the string format time information into long value, 
		//so we would know which time is the earlier by comparing the value (the smaller the earlier) 
		Date date = null;
		try {
			date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").parse(d);
		} catch (ParseException e) {
			e.printStackTrace();
		}
		return date.getTime();
	}

	// the following are some thread save setters and getters.
	public synchronized static PublicKey getPublicKey0() {
		return publicKey0;
	}

	public synchronized static void setPublicKey0(PublicKey publicKey0) {
		Blockchain.publicKey0 = publicKey0;
	}

	public synchronized static PublicKey getPublicKey1() {
		return publicKey1;
	}

	public synchronized static void setPublicKey1(PublicKey publicKey1) {
		Blockchain.publicKey1 = publicKey1;
	}

	public synchronized static PublicKey getPublicKey2() {
		return publicKey2;
	}

	public synchronized static void setPublicKey2(PublicKey publicKey2) {
		Blockchain.publicKey2 = publicKey2;
	}

	public synchronized static PrivateKey getPrivateKey0() {
		return privateKey0;
	}

	public synchronized static void setPrivateKey0(PrivateKey privateKey0) {
		Blockchain.privateKey0 = privateKey0;
	}

	public synchronized static PrivateKey getPrivateKey1() {
		return privateKey1;
	}

	public synchronized static void setPrivateKey1(PrivateKey privateKey1) {
		Blockchain.privateKey1 = privateKey1;
	}

	public synchronized static PrivateKey getPrivateKey2() {
		return privateKey2;
	}

	public synchronized static void setPrivateKey2(PrivateKey privateKey2) {
		Blockchain.privateKey2 = privateKey2;
	}

	public synchronized static Queue<BlockRecord> getBlocks() {
		return blocks;
	}

	public synchronized static void setBlocks(Queue<BlockRecord> blocks) {
		Blockchain.blocks = blocks;
	}

	public synchronized static ArrayList<BlockRecord> getBlockchain() {
		return blockchain;
	}

	public synchronized static void setBlockchain(ArrayList<BlockRecord> blockchain) {
		Blockchain.blockchain = blockchain;
	}

	public synchronized static ArrayList<BlockRecord> getTempblockchain() {
		return tempblockchain;
	}

	public synchronized static void setTempblockchain(ArrayList<BlockRecord> tempblockchain) {
		Blockchain.tempblockchain = tempblockchain;
	}

	public synchronized static int getId() {
		return id;
	}

	public synchronized static void setId(int id) {
		Blockchain.id = id;
	}

	public synchronized static void blocksAdd(BlockRecord br) {
		Blockchain.blocks.add(br);
	}

	public synchronized static void blocksAddAll(ArrayList<BlockRecord> br) {
		Blockchain.blocks.addAll(br);
	}

	public synchronized static void blockchainAdd(BlockRecord br) {
		Blockchain.blockchain.add(br);
	}

	public synchronized static void blockchainAddAll(ArrayList<BlockRecord> br) {
		Blockchain.blockchain.addAll(br);
	}

	public synchronized static void tempblockchainAdd(BlockRecord br) {
		Blockchain.tempblockchain.add(br);
	}

	public synchronized static void tempblockchainAddAll(ArrayList<BlockRecord> br) {
		Blockchain.tempblockchain.addAll(br);
	}

	public synchronized static BlockRecord blocksPoll() {
		return Blockchain.blocks.poll();
	}

	public synchronized static BlockRecord blocksPeek() {
		return Blockchain.blocks.peek();
	}

	public synchronized static PrivateKey choosePrivateKey(int id) {
		//by entering the id, return the matched private key
		if (id == 0) {
			return Blockchain.getPrivateKey0();
		} else if (id == 1) {
			return Blockchain.getPrivateKey1();
		} else {
			return Blockchain.getPrivateKey2();
		}
	}

	public synchronized static PublicKey choosePublicKey(int id) {
		//by entering the id, return the matched public key
		if (id == 0) {
			return Blockchain.getPublicKey0();
		} else if (id == 1) {
			return Blockchain.getPublicKey1();
		} else {
			return Blockchain.getPublicKey2();
		}
	}

	public synchronized static boolean allKeyReady() {
		// return ture when all of the public keys and the private key of this process are all not null
		return Blockchain.getPublicKey0() != null && Blockchain.getPublicKey1() != null
				&& Blockchain.getPublicKey2() != null && choosePrivateKey(Blockchain.getId()) != null;
	}

}

class Client implements Runnable {
	private int q_len = 6; // Number of requests to handle
	private int port; // port for client admin
	private int id;
	private String serverName;
	private String content;

	Client() {
	}

	Client(String content, String serverName, int id, int port) {
		// constructor to set port value other than the default port 5050
		this.port = port;
		this.content = content;
		this.serverName = serverName;
		this.id = id;
	}

	public synchronized void run() {
		//after the thread start, call sendOut.
		sendOut(content, serverName, id, port);
	}

	
	public synchronized void sendOut(String content, String serverName, int id, int port) {
		//send out the content to the serverName at port
		Socket sock; // socket to communicate with server.
		BufferedReader fromServer; // BufferedReader to content read from server by socket
		PrintStream toServer; // stream to write to server by socket
		String textFromServer; // content from server

		try {
			sock = new Socket(serverName, port); // create new socket to communicate with server.
			fromServer = new BufferedReader(new InputStreamReader(sock.getInputStream())); // initialize fromServer by getting input stream of the socket.
			toServer = new PrintStream(sock.getOutputStream()); // initialize toServer by getting output stream of the socket.

			toServer.println(content); 
			sock.shutdownOutput();//after the content has been sent, shutdown the output stream.
			textFromServer = fromServer.readLine(); // read first line in BufferedReader
			String combineText = "";
			while (fromServer != null && textFromServer != null) {
				combineText = combineText + textFromServer + "\n";
				textFromServer = fromServer.readLine();
			}
			if (combineText.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")) {
				//if the string is an xml string, convert it to BlockRecords object, then get the arraylist of BlockRecord objects, and add them to the blocks queue
				JAXBContext jaxbContext;
				BlockRecords blockrecords = null;
				try {
					jaxbContext = JAXBContext.newInstance(BlockRecords.class);
					Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
					blockrecords = (BlockRecords) jaxbUnmarshaller.unmarshal(new ByteArrayInputStream(combineText.getBytes()));
					Blockchain.blocksAddAll(blockrecords.getBlockRecord());
				} catch (JAXBException e) {
					e.printStackTrace();
				}
			}
			sock.close(); // close socket.
		} catch (IOException x) { // catch IO exception
			System.out.println("Socket error.");
			x.printStackTrace(); // print out where (which line) dose the errorhappen.
		}
	}
}

class FirstPort implements Runnable {
	//first port which is handling the recieving of public key and unverifed blocks.
	private int port_unverified;
	private int q_len = 6;
	private int id;

	FirstPort(int port_unverified, int id) {
		this.port_unverified = port_unverified;
		this.id = id;
	}
	public synchronized void run() {
		Socket sock;
		ServerSocket servsock;
		try {
			servsock = new ServerSocket(port_unverified, q_len);
			while (true) { // a infinite loop, make the server always checks if there is any new socket from client comes in.
				sock = servsock.accept(); // if client socket comes in, create a new socket to communicate with this client.
				new WorkerF(sock).start(); // start a thread which is a Worker to handle this socket.
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}

class SecondaryPort implements Runnable {
	// secondary port, which is to handle the update requests (blockchain).
	private int port2;
	private int id;

	SecondaryPort(int port, int id) {
		// constructor to set port value
		this.port2 = port;
		this.id = id;
	}

	public synchronized void run() {
		// a infinite loop, make the server always checks if there is any new socket from client comes in.
		int q_len = 6; // Number of requests to handle
		Socket sock;
		try {
			ServerSocket servsock = new ServerSocket(port2, q_len);
			while (true) {// waiting for new client
				sock = servsock.accept(); // if client socket comes in, create a new socket to communicate with this client.
				WorkerS workerS = new WorkerS(sock); // create new Worker object.
				workerS.start(); // start a thread which is a Worker to handle this socket.
			}
		} catch (IOException ioe) {
			System.out.println(ioe);
		}
	}
}

class Update implements Runnable {

	Update() {
	}

	public synchronized void run() {
		// a infinite loop, make the server always checks if there is any new socket from client comes in.

		while (true) {// waiting for new client
			try {
				Thread.sleep(100);
			} catch (InterruptedException e) {
				e.printStackTrace();
			}

			// get Tempblockchain and Blockchain, save them in temp array list 
			//(to avoid when for each funciton is working, some change was made to the arraylist. which would be an exception)
			ArrayList<BlockRecord> tempOtherC = Blockchain.getTempblockchain();
			ArrayList<BlockRecord> tempLocalC = Blockchain.getBlockchain();
			//if the size of tempblockchain (coming block chain) is larger, repalce blockchain (blockchain of this processs ) by it. 
			//and check which blocks in blockchain are not in coming chain, add these blocks back to the queue of blocks
			//if the 2 block chain has same length, if the coming chain has the last block which created earlier, replace the blockchain by the coming chain.
			//and check which blocks in blockchain are not in coming chain, add these blocks back to the queue of blocks
			//otherwise, do nothing. 
			if (tempOtherC.size() > tempLocalC.size()) {
				Blockchain.setBlockchain(tempOtherC);
				checkAndAddBack(tempLocalC, tempOtherC);
				Blockchain.setTempblockchain(new ArrayList<BlockRecord>());
			} else if (tempOtherC.size() == tempLocalC.size()) {
				BlockRecord oc = getLastBlock(tempOtherC);
				BlockRecord lc = getLastBlock(tempLocalC);
				if (Blockchain.convertDateToLong(oc.getCVerifiedTime()) < Blockchain.convertDateToLong(lc.getCVerifiedTime())) {
					Blockchain.setBlockchain(tempOtherC);
					checkAndAddBack(tempLocalC, tempOtherC);
					Blockchain.setTempblockchain(new ArrayList<BlockRecord>());
				}
			}
		}
	}

	public synchronized BlockRecord getLastBlock(ArrayList<BlockRecord> ab) {
		// a fuction to get the block in a arraylist that has the largest block number (last block in the chain)
		ArrayList<BlockRecord> tempbrl = ab;
		BlockRecord tempBlock = new BlockRecord("dummy");
		for (BlockRecord tempbr : tempbrl) {
			if (Integer.parseInt(tempbr.getBBlockNum()) > Integer.parseInt(tempBlock.getBBlockNum())) {
				tempBlock = tempbr;
			}
		}
		return tempBlock;
	}

	public synchronized void checkAndAddBack(ArrayList<BlockRecord> bLToAdd, ArrayList<BlockRecord> bLUsing) {
		//check which blocks in arraylist bLToAdd are not in array list bLUsing, add these blocks back to the queue of blocks
		Boolean inList = false;
		ArrayList<BlockRecord> tempLA = bLToAdd;
		ArrayList<BlockRecord> tempLU = bLUsing;
		ArrayList<BlockRecord> tempList = new ArrayList<BlockRecord>();
		for (BlockRecord brA : tempLA) {
			for (BlockRecord brU : tempLU) {
				if (brA.getABlockID().equals(brU.getABlockID())) {
					inList = true;
				}
			}
			if (!inList) {
				Blockchain.blocksAdd(resetBlock(brA));
			}
		}
	}

	public synchronized BlockRecord resetBlock(BlockRecord b) {
		//reset the block object. before adding back a block the the queue of blocks, we need to clear up 
		// the value in the field. 
		BlockRecord t = b;
		t.setASHA256String(null);
		t.setASignedSHA256(null);
		t.setAVerificationProcessID(null);
		t.setBBlockNum(null);
		t.setCVerifiedTime(null);
		t.setBPreviousHash(null);
		t.setDSeed(null);
		return t;
	}
}


class SolvePuzzle implements Runnable {

	SolvePuzzle() {
	}

	public synchronized void run() {

		System.out.flush();
		System.out.println("\nStart solving puzzles, please wait for around 30 seconds...");
		System.out.flush();
		System.out.println("\n\nNote: Sometimes when a process has finished the job, the rest of processes might need couple more seconds to finish and return the block chain."+
				"Very seldomly, process might be stuck (like every 30 times of testing?). If it does happen, please hit enter several times or re-test the"+ 
				" 3 processes again. Sorry for the inconvenience.\n\n");
		System.out.flush();
		while (true) {// waiting for new client

			if (Blockchain.allKeyReady()) {
				// if all keys are ready, start to solve puzzle.
				solve();
				if (!Blockchain.getBlockchain().isEmpty() && Blockchain.getBlockchain().size() == 13 && Blockchain.getBlocks().size() == 0 && Blockchain.getTempblockchain().size() == 0) {
					// if the blockchain is in size of 13, the queue of blocks and temp blockchain is empty, that means all the blocks are solved. leave the loop.
					System.out.flush();
					System.out.println(listToXML(Blockchain.getBlockchain()));
					System.out.flush();
					
					if (Blockchain.getId() == 0) {
						// before break the loop, if the process is p0, write the blockchain information as xml file in disk.
						try {
							PrintWriter writer;
							writer = new PrintWriter("BlockchainLedger.xml", "UTF-8");
							writer.println(listToXML(Blockchain.getBlockchain()));
							writer.close();
						} catch (FileNotFoundException e) {
							e.printStackTrace();
						} catch (UnsupportedEncodingException e) {
							e.printStackTrace();
						}
					}
					func();
					break;
				}
			}
		}
	}

	public synchronized void solve() {
		// function to solve puzzle.
		BlockRecord br1 = Blockchain.blocksPoll();
		if (br1 != null) {
			if (Blockchain.allKeyReady() && checkVerified(br1)) {
				BlockRecord br1Backup = br1; // make a copy of the input object.
				Boolean inList = false; // check if a object is already in the arraylist
				ArrayList<BlockRecord> tempList = Blockchain.getBlockchain();
				for (BlockRecord br : tempList) {
					if (br.getABlockID().equals(br1.getABlockID())) {
						inList = true;
					}
				}
				if (!inList) { // if the object is not in the array list
					ArrayList<BlockRecord> tempbrl = Blockchain.getBlockchain();
					BlockRecord tempBlock = new BlockRecord("dummy"); //create a dummy block (first block in the chain)
					for (BlockRecord tempbr : tempbrl) {// compare to each of the existing objects in the arraylist. keep the one with largest block number
						if (Integer.parseInt(tempbr.getBBlockNum()) > Integer.parseInt(tempBlock.getBBlockNum())) {
							tempBlock = tempbr;
						}
					}// so, the tempBlock is the block record which contains the largest block number (the last block)
					String previousHashString = tempBlock.getASHA256String();// get the hashed string, use it as the previous hashed string

					int seed;
					Random r = new Random();
					String hashoutput;
					try {
						while (true) {
							// solve the puzzle. add seed, hash  the  "prevous hash + the existing block record in xml string", if  
							// the result string start with 11, we say we solved the puzzle, add the time. otherwise, try it again.
//							System.out.flush();
//							System.out.println("Solving puzzle ...");
//							System.out.flush();
							seed = r.nextInt();
							br1.setDSeed(Integer.toString(seed));
							hashoutput = hashString(previousHashString + objToXML(br1));
							if (hashoutput.toUpperCase().startsWith("11")) {
								br1.setCVerifiedTime(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss.SSS").format(new Date()));
								break;
							}
						}

						//set up the field value of the block record object.
						int id = Blockchain.getId();
						br1.setBPreviousHash(previousHashString);
						br1.setAVerificationProcessID(Integer.toString(id));

						String SHA256String = hashString(objToXML(br1));
						String SignedSHA256 = "";
						br1.setASHA256String(SHA256String);
						byte[] digitalSignature;
						digitalSignature = signData(SHA256String.getBytes(), Blockchain.choosePrivateKey(id));

						SignedSHA256 = Base64.getEncoder().encodeToString(digitalSignature);
						br1.setASignedSHA256(SignedSHA256);

						//check if the previous block has been solved, if not, add the solved block to the blockchain and send out the blockchain to another 2 processes.
						//otherwise, add the block back to the queue, would solve it again later.
						Boolean beenSolved = false;
						ArrayList<BlockRecord> tempList2 = Blockchain.getBlockchain();
						for (BlockRecord br : tempList2) {
							if (br.getBPreviousHash().equals(tempBlock.getASHA256String())) {
								beenSolved = true;
							}
						}
						if (!beenSolved) {
							int blockNum = Integer.parseInt(tempBlock.getBBlockNum()) + 1;
							br1.setBBlockNum(Integer.toString(blockNum));
							Blockchain.blockchainAdd(br1);
							Blockchain.sendToOtherProcesses(listToXML(Blockchain.getBlockchain()), "localhost",Blockchain.getId(), "up");
						} else {
							Blockchain.blocksAdd(br1Backup);
						}
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		}
	}

	public synchronized void func(){
		// function to display blocks, check the credit of processes and hash verify check.
		BufferedReader in = new BufferedReader(new InputStreamReader(System.in)); //read in user command input.
		try{
			String input;
			do {
				System.out.flush ();
				System.out.println("\n Please enter additional commands: "); //print hint about what to enter.
				System.out.flush (); // flush streams
				System.out.println("\"L\" to list all blocks; \"V\" to check credit of each process;\"V hash\" to check the hash of whole blockchain; "); //print hint about what to enter.
				System.out.flush (); // flush streams
				System.out.println("\"quit\" to leave;"); //print hint about what to enter.
				System.out.flush (); // flush streams
				
				input = in.readLine(); // get input content
				if(input!=null && input.indexOf("quit") < 0){ // if there is no "quit" entered, go on
					ArrayList <BlockRecord> brL = Blockchain.getBlockchain();// get the blockchain
					if(input.toUpperCase().startsWith("L")){
						// if "L" entered in console, print all the block record in line
						for (BlockRecord b :brL){
							System.out.flush ();
							System.out.println(b.getBBlockNum()+". "+b.getCCreatedTime()+ " "+b.getFFname()+" "+b.getFLname()+" "+b.getFDOB()+" " +b.getFSSNum()+" "+ b.getGDiag()+" "+b.getGTreat()+" "+b.getGRx());
							System.out.flush ();
						}
					}else if (input.toUpperCase().startsWith("V")&&!input.toUpperCase().startsWith("V ")){
						// if "V" entered, the credit of each process will be returned.
						int [] lst = {0,0,0};
						for (BlockRecord b :brL){
							if (b.getAVerificationProcessID().equals("0")) lst[0] = lst[0]+1;
							if (b.getAVerificationProcessID().equals("1")) lst[1] = lst[1]+1;
							if (b.getAVerificationProcessID().equals("2")) lst[2] = lst[2]+1;
						}
						System.out.flush ();
						System.out.println("Credit: P0="+lst[0]+ ", P1="+lst[1]+", P2="+lst[2]);
						System.out.flush ();
					}else if (input.toUpperCase().startsWith("V HASH")){
						// if "V hash" entered, the function would set the block record object back to its fields value before hash
						// then rety hashing by adding the previous block's hash value as previous-hash field. if the new hash string
						// equals to the original hash string, we say it is verified. 
						ArrayList <BlockRecord> badBlocks = new ArrayList <BlockRecord> ();
						ArrayList <BlockRecord> tempL=brL;
						BlockRecord tb1= new BlockRecord();
						BlockRecord tb2= new BlockRecord();
						for(int i =1; i< 12; i++){
							// use index, since block 0 is dummy block, we start with block 1
							for (BlockRecord b :brL){
								if (b.getBBlockNum()!=null&&b.getBBlockNum().equals(Integer.toString(i))) tb1 = b;
							}
							for(BlockRecord t :tempL){
								if (t.getBBlockNum()!=null && t.getBBlockNum().equals(Integer.toString(i+1))) tb2 =t;
							}
							// setting the block fields back to its status before hashing
							String prehash= tb1.getASHA256String();
							String hash=tb2.getASHA256String();
							tb2.setBBlockNum(null);
							tb2.setASHA256String(null);
							tb2.setBPreviousHash(prehash);
							tb2.setASignedSHA256(null);
							if (!hashString(objToXML(tb2)).equals(hash)&&tb2.getBBlockNum()!=null){
								// if the new hash string is not equals to the original one, we save it into bad block array list.
								badBlocks.add(tb2);
							}
						}
						if (badBlocks.size()==0){
							// if no bad blocks
							System.out.flush ();
							System.out.println("All blocks have been verified");
							System.out.flush ();
						}else{
							// if bad blocks exist, print out the block numbers
							String t ="";
							for(BlockRecord bb : badBlocks ){
								t=t+bb.getBBlockNum()+". ";
							}
							System.out.flush ();
							System.out.println("Most blocks have been verified, except block: "+t);
							System.out.flush ();
						}
					}
				}
				if (input!=null&&input.contains("quit")) break;
			}while (true); //keep reading in what user entered, until "quit" entered by user 
			System.exit(0);
		} catch (IOException x) {
			x.printStackTrace (); //catch IO exception, and print out where (which line) dose the error happen.
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	public static synchronized boolean checkVerified(BlockRecord br) {
		// function to check if the block id in the block record object has been corrected signed (check the signed block id)
		boolean verified = false;
		if (br != null) {
			try {
				byte[] b1 = br.getABlockID().getBytes();
				PublicKey p1 = Blockchain.choosePublicKey(Integer.parseInt(br.getACreatingProcess()));
				byte[] b2 = Base64.getDecoder().decode(br.getBSignedBlockID());
				verified = verifySig(b1, p1, b2);
			} catch (NumberFormatException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return verified;
	}

	public static synchronized String hashString(String s) throws Exception {
		// function to hash string in sha-256
		MessageDigest md;
		md = MessageDigest.getInstance("SHA-256");
		md.update(s.getBytes());
		byte byteData[] = md.digest();
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < byteData.length; i++) {
			sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
		}
		String SHA256String = sb.toString();
		return SHA256String;
	}

	public static synchronized byte[] signData(byte[] data, PrivateKey key) throws Exception {
		// function to sign string.
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(key);
		signer.update(data);
		return (signer.sign());
	}

	public static synchronized boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		// function to verify whether a string has been signed.
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);
		return (signer.verify(sig));
	}

	public synchronized String objToXML(BlockRecord br) {
		// convert a block record object to xml format string 
		StringWriter sw = new StringWriter();
		JAXBContext jaxbContext;
		try {
			jaxbContext = JAXBContext.newInstance(BlockRecord.class);
			Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);
			jaxbMarshaller.marshal(br, sw);
		} catch (JAXBException e) {
			e.printStackTrace();
		}
		String fullBlock = sw.toString();
		String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
		String cleanBlock = fullBlock.replace(XMLHeader, "");
		String XMLBlock = XMLHeader + "\n<BlockLedger>" + cleanBlock + "</BlockLedger>";
		return XMLBlock;
	}

	public synchronized BlockRecord XMLtoObj(String combineText) {
		// a function to convert xml format to block record object (if the xml string only contains information for one object)
		JAXBContext jaxbContext;
		BlockRecords blockrecords = null;
		try {
			jaxbContext = JAXBContext.newInstance(BlockRecords.class);
			Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
			blockrecords = (BlockRecords) jaxbUnmarshaller.unmarshal(new ByteArrayInputStream(combineText.getBytes()));
		} catch (JAXBException e) {
			e.printStackTrace();
		}
		ArrayList<BlockRecord> tempList = blockrecords.getBlockRecord();
		BlockRecord tempBr = null;
		for (BlockRecord b : tempList) {
			tempBr = b;
		}
		return tempBr;
	}

	public synchronized String listToXML(ArrayList<BlockRecord> brs) {
		// a function to convert block record arraylist to xml format string.
		String XMLBlock = null;
		try {
			JAXBContext jaxbContext = JAXBContext.newInstance(BlockRecord.class);
			Marshaller jaxbMarshaller = jaxbContext.createMarshaller();
			StringWriter sw = new StringWriter();

			jaxbMarshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, true);

			String stringXML = sw.toString();
			ArrayList<BlockRecord> cp = brs;

			for (BlockRecord b : cp) {
				jaxbMarshaller.marshal(b, sw);
			}

			String fullBlock = sw.toString();
			String XMLHeader = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>";
			String cleanBlock = fullBlock.replace(XMLHeader, "");
			XMLBlock = XMLHeader + "\n<BlockLedger>" + cleanBlock + "</BlockLedger>";
		} catch (JAXBException e) {
			e.printStackTrace();
		}
		return XMLBlock;
	}

	public synchronized ArrayList<BlockRecord> XMLToList(String combineText) {
		//a function to convert xml string to block record arraylist
		if (combineText.startsWith("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>")) {
			JAXBContext jaxbContext;
			BlockRecords blockrecords = null;
			try {
				jaxbContext = JAXBContext.newInstance(BlockRecords.class);
				Unmarshaller jaxbUnmarshaller = jaxbContext.createUnmarshaller();
				blockrecords = (BlockRecords) jaxbUnmarshaller.unmarshal(new ByteArrayInputStream(combineText.getBytes()));
			} catch (JAXBException e) {
				e.printStackTrace();
			}
			return blockrecords.getBlockRecord();
		}
		return null;
	}
}


@XmlRootElement
class BlockRecord {
	//block record object, set it read for xml format
	String SHA256String;
	String SignedSHA256;
	String BlockID;
	String VerificationProcessID;
	String CreatingProcess;
	String Fname;
	String Lname;
	String SSNum;
	String DOB;
	String Diag;
	String Treat;
	String Rx;

	String BlockNum;
	String VerifiedTime;
	String PreviousHash;
	String Seed;
	String SignedBlockID;
	String CreatedTime;

	BlockRecord() {}

	BlockRecord(String s) {
		if (s.equals("dummy")) {
			this.SHA256String = "dummy";
			this.SignedSHA256 = "dummy";
			this.BlockID = "dummy";
			this.VerificationProcessID = "dummy";
			this.CreatingProcess = "dummy";
			this.Fname = "dummy";
			this.Lname = "dummy";
			this.SSNum = "dummy";
			this.DOB = "dummy";
			this.Diag = "dummy";
			this.Treat = "dummy";
			this.Rx = "dummy";

			this.BlockNum = "0";
			this.VerifiedTime = "1900-01-01 11:11:11.111";
			this.PreviousHash = "Predummy";
			this.Seed = "0";
			this.SignedBlockID = "dummy";
			this.CreatedTime = "1900-01-01 11:11:11.111";
		}
	}

	public String getASHA256String() {
		return SHA256String;
	}

	@XmlElement
	public void setASHA256String(String SH) {
		this.SHA256String = SH;
	}

	public String getASignedSHA256() {
		return SignedSHA256;
	}

	@XmlElement
	public void setASignedSHA256(String SH) {
		this.SignedSHA256 = SH;
	}

	public String getACreatingProcess() {
		return CreatingProcess;
	}

	@XmlElement
	public void setACreatingProcess(String CP) {
		this.CreatingProcess = CP;
	}

	public String getAVerificationProcessID() {
		return VerificationProcessID;
	}

	@XmlElement
	public void setAVerificationProcessID(String VID) {
		this.VerificationProcessID = VID;
	}

	public String getABlockID() {
		return BlockID;
	}

	@XmlElement
	public void setABlockID(String BID) {
		this.BlockID = BID;
	}

	public String getFSSNum() {
		return SSNum;
	}

	@XmlElement
	public void setFSSNum(String SS) {
		this.SSNum = SS;
	}

	public String getFFname() {
		return Fname;
	}

	@XmlElement
	public void setFFname(String FN) {
		this.Fname = FN;
	}

	public String getFLname() {
		return Lname;
	}

	@XmlElement
	public void setFLname(String LN) {
		this.Lname = LN;
	}

	public String getFDOB() {
		return DOB;
	}

	@XmlElement
	public void setFDOB(String DOB) {
		this.DOB = DOB;
	}

	public String getGDiag() {
		return Diag;
	}

	@XmlElement
	public void setGDiag(String D) {
		this.Diag = D;
	}

	public String getGTreat() {
		return Treat;
	}

	@XmlElement
	public void setGTreat(String D) {
		this.Treat = D;
	}

	public String getGRx() {
		return Rx;
	}

	@XmlElement
	public void setGRx(String D) {
		this.Rx = D;
	}

	public String getBSignedBlockID() {
		return SignedBlockID;
	}

	@XmlElement
	public void setBSignedBlockID(String D) {
		this.SignedBlockID = D;
	}

	public String getBBlockNum() {
		return BlockNum;
	}

	@XmlElement
	public void setBBlockNum(String D) {
		this.BlockNum = D;
	}

	public String getBPreviousHash() {
		return PreviousHash;
	}

	@XmlElement
	public void setBPreviousHash(String D) {
		this.PreviousHash = D;
	}

	public String getCVerifiedTime() {
		return VerifiedTime;
	}

	@XmlElement
	public void setCVerifiedTime(String D) {
		this.VerifiedTime = D;
	}

	public String getCCreatedTime() {
		return CreatedTime;
	}

	@XmlElement
	public void setCCreatedTime(String D) {
		this.CreatedTime = D;
	}

	public String getDSeed() {
		return Seed;
	}

	@XmlElement
	public void setDSeed(String D) {
		this.Seed = D;
	}

}

@XmlRootElement(name = "BlockLedger")
// @XmlAccessorType (XmlAccessType.FIELD)
class BlockRecords { //a object which contains an array of block record objects.
	@XmlElement(name = "BlockRecord")
	private ArrayList<BlockRecord> blockLedger = null;

	public ArrayList<BlockRecord> getBlockRecord() {
		return blockLedger;
	}

	public void setBlockRecord(ArrayList<BlockRecord> blockLedger) {
		this.blockLedger = blockLedger;
	}
}
