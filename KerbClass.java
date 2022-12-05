package Kerb;

import java.io.UnsupportedEncodingException;

import com.intel.crypto.Random;
import com.intel.langutil.ArrayUtils;
import com.intel.util.*;

//
// Implementation of DAL Trusted Application: Kerberos 
//
// **************************************************************************************************
// NOTE:  This default Trusted Application implementation is intended for DAL API Level 7 and above
// **************************************************************************************************

public class KerbClass extends IntelApplet {

	final int StorageSize = 712;
	final int GETSTORAGECMD = 1;
	final int EDITSTORAGECMD = 2;
	final int GETRANDCMD = 3;

	/**
	 * This method will be called by the VM when a new session is opened to the Trusted Application 
	 * and this Trusted Application instance is being created to handle the new session.
	 * This method cannot provide response data and therefore calling
	 * setResponse or setResponseCode methods from it will throw a NullPointerException.
	 * 
	 * @param	request	the input data sent to the Trusted Application during session creation
	 * 
	 * @return	APPLET_SUCCESS if the operation was processed successfully, 
	 * 		any other error status code otherwise (note that all error codes will be
	 * 		treated similarly by the VM by sending "cancel" error code to the SW application).
	 */
	public int onInit(byte[] request) {
		DebugPrint.printString("Hello, DAL!");
		return APPLET_SUCCESS;
	}
	
	/**
	 * This method will be called by the VM to handle a command sent to this
	 * Trusted Application instance.
	 * 
	 * @param	commandId	the command ID (Trusted Application specific) 
	 * @param	request		the input data for this command 
	 * @return	the return value should not be used by the applet
	 */
	public int invokeCommand(int commandId, byte[] request) {
		
		DebugPrint.printString("Received command Id: " + commandId + ".");
		if(request != null)
		{
			byte[] myResponse = {'F', 'a', 'i' ,'l'};
			DebugPrint.printString("Received buffer:");
			DebugPrint.printBuffer(request);
	        String string = new String(request);
	        DebugPrint.printString("Received string: " + string);
	        switch(commandId)
	        {
	        case GETSTORAGECMD:
	        	myResponse = ReadBytesFromMVM();
	        	break;
	        case EDITSTORAGECMD:
	        	if(StoreUsersToNVM(request))
		        	myResponse = "OK".getBytes();
	        	else
	        		myResponse = "Failed".getBytes();
	        	break;
	        case GETRANDCMD:
				myResponse = getRandom();
				break;
	        default:
				break;
	        }
	        
			setResponse(myResponse, 0, myResponse.length);
			setResponseCode(commandId);
	       
	        String stored = ReadStringFromMVM();
	        DebugPrint.printString("Currently stored: " + stored);
		}
		

		/*
		 * To return the response data to the command, call the setResponse
		 * method before returning from this method. 
		 * Note that calling this method more than once will 
		 * reset the response data previously set.
		 */

		/*
		 * In order to provide a return value for the command, which will be
		 * delivered to the SW application communicating with the Trusted Application,
		 * setResponseCode method should be called. 
		 * Note that calling this method more than once will reset the code previously set. 
		 * If not set, the default response code that will be returned to SW application is 0.
		 */

		/*
		 * The return value of the invokeCommand method is not guaranteed to be
		 * delivered to the SW application, and therefore should not be used for
		 * this purpose. Trusted Application is expected to return APPLET_SUCCESS code 
		 * from this method and use the setResposeCode method instead.
		 */
		return APPLET_SUCCESS;
	}
	
	private String ReadStringFromMVM() {
		try {			
			byte[] stored = new byte[StorageSize];
			FlashStorage.readFlashData(0, stored, 0);
			byte[] emptyArray = new byte[1];
			int end = ArrayUtils.findInByteArray(emptyArray, 0, emptyArray.length, stored, 0, stored.length);
			byte[] current_stored = new byte[end];
			ArrayUtils.copyByteArray(stored, 0, current_stored, 0, current_stored.length);
			DebugPrint.printString("Current buffer stored is: ");
			DebugPrint.printBuffer(current_stored);
			String string_stored = new String(current_stored);
			DebugPrint.printString("Current buffer in string is: ");
			DebugPrint.printString(string_stored);
			return string_stored;
		}
	catch (Exception e) {
		return "None";
	}
	}
	
	private byte[] ReadBytesFromMVM() {
		try {			
			byte[] stored = new byte[StorageSize];
			FlashStorage.readFlashData(0, stored, 0);
			byte[] emptyArray = new byte[1];
			int end = ArrayUtils.findInByteArray(emptyArray, 0, emptyArray.length, stored, 0, stored.length);
			byte[] current_stored = new byte[end];
			ArrayUtils.copyByteArray(stored, 0, current_stored, 0, current_stored.length);
			DebugPrint.printString("Current buffer stored is: ");
			DebugPrint.printBuffer(current_stored);
			return current_stored;
		}
	catch (Exception e) {
		return "".getBytes();
	}
	}

	private boolean StoreUsersToNVM(byte[] data) {
        if(data.length == 0)
        {
        	DebugPrint.printString("1");
			FlashStorage.eraseFlashData(0);
			return true;
        }

		try {			
			FlashStorage.readFlashData(0, new byte[StorageSize], 0);
			FlashStorage.eraseFlashData(0);
			FlashStorage.writeFlashData(0, data, 0, data.length);
			return true;
		}
		catch (Exception e) {
			FlashStorage.writeFlashData(0, data, 0, data.length);
			return true;
			}
	}
	
	private byte[] getRandom() {
		byte[] rand_bytes = new byte[128];
		Random.getRandomBytes(rand_bytes, (short)0, (short)128);
		return rand_bytes;
	}

	/**
	 * This method will be called by the VM when the session being handled by
	 * this Trusted Application instance is being closed 
	 * and this Trusted Application instance is about to be removed.
	 * This method cannot provide response data and therefore
	 * calling setResponse or setResponseCode methods from it will throw a NullPointerException.
	 * 
	 * @return APPLET_SUCCESS code (the status code is not used by the VM).
	 */
	public int onClose() {
		DebugPrint.printString("Goodbye, DAL!");
		return APPLET_SUCCESS;
	}
}
