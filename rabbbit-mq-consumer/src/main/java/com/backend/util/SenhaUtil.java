package com.backend.util;

import java.nio.charset.StandardCharsets;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class SenhaUtil {

	private static final String PASSWORD = "senha123"; // Senha para derivar a chave
    private static final String SALT = "salt123"; // Salt para derivar a chave
    private static final int KEY_LENGTH = 128; // Comprimento da chave em bits

	
	public static String calculaComplexidade(String pwd) {

		int nScore = 0, nLength = 0, nAlphaUC = 0, nAlphaLC = 0, nNumber = 0, nSymbol = 0, nMidChar = 0,
				nRequirements = 0, nAlphasOnly = 0, nNumbersOnly = 0, nUnqChar = 0, nRepChar = 0, nRepInc = 0,
				nConsecAlphaUC = 0, nConsecAlphaLC = 0, nConsecNumber = 0, nConsecSymbol = 0, nConsecCharType = 0,
				nSeqAlpha = 0, nSeqNumber = 0, nSeqSymbol = 0, nSeqChar = 0, nReqChar = 0, nMultConsecCharType = 0;
		int nMultRepChar = 1, nMultConsecSymbol = 1;
		int nMultMidChar = 2, nMultRequirements = 2, nMultConsecAlphaUC = 2, nMultConsecAlphaLC = 2,
				nMultConsecNumber = 2;
		int nReqCharType = 3, nMultAlphaUC = 3, nMultAlphaLC = 3, nMultSeqAlpha = 3, nMultSeqNumber = 3,
				nMultSeqSymbol = 3;
		int nMultLength = 4, nMultNumber = 4;
		int nMultSymbol = 6;
		String nTmpAlphaUC = "", nTmpAlphaLC = "", nTmpNumber = "", nTmpSymbol = "";
		String sAlphaUC = "0", sAlphaLC = "0", sNumber = "0", sSymbol = "0", sMidChar = "0", sRequirements = "0",
				sAlphasOnly = "0", sNumbersOnly = "0", sRepChar = "0", sConsecAlphaUC = "0", sConsecAlphaLC = "0",
				sConsecNumber = "0", sSeqAlpha = "0", sSeqNumber = "0", sSeqSymbol = "0";
		String sAlphas = "abcdefghijklmnopqrstuvwxyz";
		String sNumerics = "01234567890";
		String sSymbols = ")!@#$%^&*(";
		String sComplexity = "Too Short";
		String sStandards = "Below";
		int nMinPwdLen = 8;

		int nd;
		if (System.getProperty("os.name").toLowerCase().contains("windows")) {
			nd = 0;
		} else {
			nd = 1;
		}

		if (pwd != null) {
			nScore = pwd.length() * nMultLength;
			nLength = pwd.length();
			String[] arrPwd = pwd.replaceAll("\\s+", "").split("\\s*");
			int arrPwdLen = arrPwd.length;

			// Loop through password to check for Symbol, Numeric, Lowercase and Uppercase
			// pattern matches
			for (int a = 0; a < arrPwdLen; a++) {
				if (Pattern.matches("[A-Z]", arrPwd[a])) {
					if (!nTmpAlphaUC.equals("")) {
						if ((Integer.parseInt(nTmpAlphaUC) + 1) == a) {
							nConsecAlphaUC++;
							nConsecCharType++;
						}
					}
					nTmpAlphaUC = String.valueOf(a);
					nAlphaUC++;
				} else if (Pattern.matches("[a-z]", arrPwd[a])) {
					if (!nTmpAlphaLC.equals("")) {
						if ((Integer.parseInt(nTmpAlphaLC) + 1) == a) {
							nConsecAlphaLC++;
							nConsecCharType++;
						}
					}
					nTmpAlphaLC = String.valueOf(a);
					nAlphaLC++;
				} else if (Pattern.matches("[0-9]", arrPwd[a])) {
					if (a > 0 && a < (arrPwdLen - 1)) {
						nMidChar++;
					}
					if (!nTmpNumber.equals("")) {
						if ((Integer.parseInt(nTmpNumber) + 1) == a) {
							nConsecNumber++;
							nConsecCharType++;
						}
					}
					nTmpNumber = String.valueOf(a);
					nNumber++;
				} else if (Pattern.matches("[^a-zA-Z0-9_]", arrPwd[a])) {
					if (a > 0 && a < (arrPwdLen - 1)) {
						nMidChar++;
					}
					if (!nTmpSymbol.equals("")) {
						if ((Integer.parseInt(nTmpSymbol) + 1) == a) {
							nConsecSymbol++;
							nConsecCharType++;
						}
					}
					nTmpSymbol = String.valueOf(a);
					nSymbol++;
				}

				// Internal loop through password to check for repeat characters
				boolean bCharExists = false;
				for (int b = 0; b < arrPwdLen; b++) {
					if (arrPwd[a].equals(arrPwd[b]) && a != b) {
						// repeat character exists
						bCharExists = true;

						/*
						 * Calculate increment deduction based on proximity to identical characters
						 * Deduction is incremented each time a new match is discovered Deduction amount
						 * is based on total password length divided by the difference of distance
						 * between currently selected match
						 */
						nRepInc += Math.abs(arrPwdLen / (b - a));
					}
				}
				if (bCharExists) {
					nRepChar++;
					nUnqChar = arrPwdLen - nRepChar;
					nRepInc = (nUnqChar != 0) ? (int) Math.ceil(nRepInc / nUnqChar) : (int) Math.ceil(nRepInc);
				}
			}

			// Check for sequential alpha string patterns (forward and reverse)
			for (int s = 0; s < 23; s++) {
				String sFwd = sAlphas.substring(s, s + 3);
				StringBuilder sb = new StringBuilder(sFwd);
				String sRev = sb.reverse().toString();
				if (pwd.toLowerCase().contains(sFwd) || pwd.toLowerCase().contains(sRev)) {
					nSeqAlpha++;
					nSeqChar++;
				}
			}

			// Check for sequential numeric string patterns (forward and reverse)
			for (int s = 0; s < 8; s++) {
				String sFwd = sNumerics.substring(s, s + 3);
				StringBuilder sb = new StringBuilder(sFwd);
				String sRev = sb.reverse().toString();
				if (pwd.toLowerCase().contains(sFwd) || pwd.toLowerCase().contains(sRev)) {
					nSeqNumber++;
					nSeqChar++;
				}
			}

			// Check for sequential symbol string patterns (forward and reverse)
			for (int s = 0; s < 8; s++) {
				String sFwd = sSymbols.substring(s, s + 3);
				StringBuilder sb = new StringBuilder(sFwd);
				String sRev = sb.reverse().toString();
				if (pwd.toLowerCase().contains(sFwd) || pwd.toLowerCase().contains(sRev)) {
					nSeqSymbol++;
					nSeqChar++;
				}
			}

			// Modify overall score value based on usage vs requirements

			// General point assignment
			//System.out.println("+ " + nScore);
			if (nAlphaUC > 0 && nAlphaUC < nLength) {
				nScore += (nLength - nAlphaUC) * 2;
				sAlphaUC = "+ " + (nLength - nAlphaUC) * 2;
			}
			if (nAlphaLC > 0 && nAlphaLC < nLength) {
				nScore += (nLength - nAlphaLC) * 2;
				sAlphaLC = "+ " + (nLength - nAlphaLC) * 2;
			}
			if (nNumber > 0 && nNumber < nLength) {
				nScore += nNumber * nMultNumber;
				sNumber = "+ " + nNumber * nMultNumber;
			}
			if (nSymbol > 0) {
				nScore += nSymbol * nMultSymbol;
				sSymbol = "+ " + nSymbol * nMultSymbol;
			}
			if (nMidChar > 0) {
				nScore += nMidChar * nMultMidChar;
				sMidChar = "+ " + nMidChar * nMultMidChar;
			}
			//System.out.println(sAlphaUC);
			//System.out.println(sAlphaLC);
			//System.out.println(sNumber);
			//System.out.println(sSymbol);
			//System.out.println(sMidChar);

			// Point deductions for poor practices
			if ((nAlphaLC > 0 || nAlphaUC > 0) && nSymbol == 0 && nNumber == 0) {
				// Only Letters
				nScore -= nLength;
				nAlphasOnly = nLength;
				sAlphasOnly = "- " + nLength;
			}
			if (nAlphaLC == 0 && nAlphaUC == 0 && nSymbol == 0 && nNumber > 0) {
				// Only Numbers
				nScore -= nLength;
				nNumbersOnly = nLength;
				sNumbersOnly = "- " + nLength;
			}
			if (nRepChar > 0) {
				// Same character exists more than once
				nScore -= nRepInc;
				sRepChar = "- " + nRepInc;
			}
			if (nConsecAlphaUC > 0) {
				// Consecutive Uppercase Letters exist
				nScore -= nConsecAlphaUC * nMultConsecAlphaUC;
				sConsecAlphaUC = "- " + nConsecAlphaUC * nMultConsecAlphaUC;
			}
			if (nConsecAlphaLC > 0) {
				// Consecutive Lowercase Letters exist
				nScore -= nConsecAlphaLC * nMultConsecAlphaLC;
				sConsecAlphaLC = "- " + nConsecAlphaLC * nMultConsecAlphaLC;
			}
			if (nConsecNumber > 0) {
				// Consecutive Numbers exist
				nScore -= nConsecNumber * nMultConsecNumber;
				sConsecNumber = "- " + nConsecNumber * nMultConsecNumber;
			}
			if (nSeqAlpha > 0) {
				// Sequential alpha strings exist (3 characters or more)
				nScore -= nSeqAlpha * nMultSeqAlpha;
				sSeqAlpha = "- " + nSeqAlpha * nMultSeqAlpha;
			}
			if (nSeqNumber > 0) {
				// Sequential numeric strings exist (3 characters or more)
				nScore -= nSeqNumber * nMultSeqNumber;
				sSeqNumber = "- " + nSeqNumber * nMultSeqNumber;
			}
			if (nSeqSymbol > 0) {
				// Sequential symbol strings exist (3 characters or more)
				nScore -= nSeqSymbol * nMultSeqSymbol;
				sSeqSymbol = "- " + nSeqSymbol * nMultSeqSymbol;
			}
			//System.out.println(sAlphasOnly);
			//System.out.println(sNumbersOnly);
			//System.out.println(sRepChar);
			//System.out.println(sConsecAlphaUC);
			//System.out.println(sConsecAlphaLC);
			//System.out.println(sConsecNumber);
			//System.out.println(sSeqAlpha);
			//System.out.println(sSeqNumber);
			//System.out.println(sSeqSymbol);

			// Determine if mandatory requirements have been met and set image indicators
			// accordingly
			int[] arrChars = { nLength, nAlphaUC, nAlphaLC, nNumber, nSymbol };
			String[] arrCharsIds = { "nLength", "nAlphaUC", "nAlphaLC", "nNumber", "nSymbol" };
			int arrCharsLen = arrChars.length;
			for (int c = 0; c < arrCharsLen; c++) {
				//System.out.println(arrCharsIds[c] + ": " + arrChars[c]);
				if (arrCharsIds[c].equals("nLength")) {
					int minVal = nMinPwdLen - 1;
					if (arrChars[c] == minVal + 1) {
						nReqChar++;
					} else if (arrChars[c] > minVal + 1) {
						nReqChar++;
					}
				} else {
					if (arrChars[c] == 0) {
						continue;
					}
					nReqChar++;
				}
			}
			nRequirements = nReqChar;
			int nMinReqChars = (pwd.length() >= nMinPwdLen) ? 3 : 4;
			if (nRequirements > nMinReqChars) {
				// One or more required characters exist
				nScore += nRequirements * 2;
				sRequirements = "+ " + nRequirements * 2;
			}
			//System.out.println(sRequirements);

			// Determine if additional bonuses need to be applied and set image indicators
			// accordingly
			int[] arrCharsAdditional = { nMidChar, nRequirements };
			String[] arrCharsIdsAdditional = { "nMidChar", "nRequirements" };
			int arrCharsLenAdditional = arrCharsAdditional.length;
			for (int c = 0; c < arrCharsLenAdditional; c++) {
				//System.out.println(arrCharsIdsAdditional[c] + ": " + arrCharsAdditional[c]);
				if (arrCharsAdditional[c] > 0) {
					// warn
				} else {
					// pass
				}
			}

			// Determine if suggested requirements have been met and set image indicators
			// accordingly
			int[] arrCharsSuggested = { nAlphasOnly, nNumbersOnly, nRepChar, nConsecAlphaUC, nConsecAlphaLC,
					nConsecNumber, nSeqAlpha, nSeqNumber, nSeqSymbol };
			String[] arrCharsIdsSuggested = { "nAlphasOnly", "nNumbersOnly", "nRepChar", "nConsecAlphaUC",
					"nConsecAlphaLC", "nConsecNumber", "nSeqAlpha", "nSeqNumber", "nSeqSymbol" };
			int arrCharsLenSuggested = arrCharsSuggested.length;
			for (int c = 0; c < arrCharsLenSuggested; c++) {
				//System.out.println(arrCharsIdsSuggested[c] + ": " + arrCharsSuggested[c]);
				if (arrCharsSuggested[c] > 0) {
					// warn
				} else {
					// pass
				}
			}

			// Determine complexity based on overall score
			if (nScore > 100) {
				nScore = 100;
			} else if (nScore < 0) {
				nScore = 0;
			}
			if (nScore >= 0 && nScore < 20) {
				sComplexity = "Very Weak";
			} else if (nScore >= 20 && nScore < 40) {
				sComplexity = "Weak";
			} else if (nScore >= 40 && nScore < 60) {
				sComplexity = "Good";
			} else if (nScore >= 60 && nScore < 80) {
				sComplexity = "Strong";
			} else if (nScore >= 80 && nScore <= 100) {
				sComplexity = "Very Strong";
			}

		}
		return sComplexity;
	}
	
	 public static String encryptPassword(String password) {
	        try {
	            // Derivar a chave usando PBKDF2
	            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
	            KeySpec spec = new PBEKeySpec(PASSWORD.toCharArray(), SALT.getBytes(), 10000, KEY_LENGTH);
	            SecretKeySpec secretKeySpec = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");

	            Cipher cipher = Cipher.getInstance("AES");
	            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

	            byte[] encryptedBytes = cipher.doFinal(password.getBytes(StandardCharsets.UTF_8));
	            return Base64.getEncoder().encodeToString(encryptedBytes);
	        } catch (Exception e) {
	            e.printStackTrace();
	            return null;
	        }
	    }

}
