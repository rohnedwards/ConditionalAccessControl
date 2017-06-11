/*
This code is from this Gist: https://gist.github.com/rohnedwards/b5e7ca34a062d765bf4a
Demo can be found here: https://rohnspowershellblog.wordpress.com/2015/08/29/reading-and-creating-conditional-aces-with-powershell-kind-of/
*/

using System;
using System.Security.Principal;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Testing {

	public enum ConditionalAceTokenLiteralBaseType : byte {
		Octal = 0x01,
		Decimal = 0x02,
		Hexadecimal = 0x03
	}

	public enum ConditionalAceTokenLiteralSignType : byte {
		Positive = 0x01,
		Negative = 0x02,
		None = 0x03
	}

	public enum ConditionalAceTokenByteCode : byte {
		Padding = 0x00,
		Int8 = 0x01,
		Int16 = 0x02,
		Int32 = 0x03,
		Int64 = 0x04,
		UnicodeString = 0x10,
		OctetString = 0x18,
		Composite = 0x50,
		Sid = 0x51,
		Equals = 0x80,
		NotEquals = 0x81,
		LessThan = 0x82,
		LessThanOrEqualTo = 0x83,
		GreaterThan = 0x84,
		GreaterThanOrEqualTo = 0x85,
		Contains = 0x86,
		Exists = 0x87,
		AnyOf = 0x88,
		Member_of = 0x89,
		Device_Member_of = 0x8a,
		Member_of_Any = 0x8b,
		Device_Member_of_Any = 0x8c,
		Not_Exists = 0x8d,
		NotContains = 0x8e,
		NotAnyOf = 0x8f,
		Not_Member_of = 0x90,
		Not_Device_Member_of = 0x91,
		Not_Member_of_Any = 0x92,
		Not_Device_Member_of_Any = 0x93,
		And = 0xa0,
		Or = 0xa1,
		Not = 0xa2,
		LocalAttribute = 0xf8,
		UserAttribute = 0xf9,
		ResourceAttribute = 0xfa,
		DeviceAttribute = 0xfb

	}

	internal enum ConditionalAceOperatorTokenType {
		Unary,
		Binary
	}

	public abstract class ConditionalAceConditionOperand {
		internal abstract byte[] _BinaryForm { get; }

		public int BinaryLength {
			get {
				return _BinaryForm.Length;
			}
		}

		public void GetBinaryForm(byte[] binaryForm, int offset) {
				_BinaryForm.CopyTo(binaryForm, offset);
		}
	}

	public class ConditionalAceConditionalLiteralOperand : ConditionalAceConditionOperand {
		public ConditionalAceConditionalLiteralOperand(ConditionalAceLiteralToken token) {
			this.LiteralToken = token;
		}

		public ConditionalAceLiteralToken LiteralToken { get; set; }
		internal override byte[] _BinaryForm {
			get {
				return this.LiteralToken._BinaryForm;
			}
		}

		public override string ToString() {
			return this.LiteralToken.ToString();
		}
	}

	public abstract class ConditionalAceCondition : ConditionalAceConditionOperand {

		public ConditionalAceCondition(ConditionalAceOperatorToken operatorToken) {
			this.Operator = operatorToken;
		}

		public ConditionalAceOperatorToken Operator { get; set; }

		public static ConditionalAceCondition GetConditionalAceCondition(byte[] binaryForm) {

			// Check signature here

			int offset = 4;
			int length = binaryForm.Length - 4;
			var stack = new Stack<ConditionalAceConditionOperand>();

			// https://msdn.microsoft.com/en-us/library/hh877855.aspx
			foreach (var token in ConditionalAceToken.GetTokens(binaryForm, offset, length)) {
				if (token is ConditionalAceLiteralToken) {
					if (!(token is ConditionalAcePaddingToken)) {
						stack.Push(new ConditionalAceConditionalLiteralOperand((ConditionalAceLiteralToken) token));
					}
				}
				else if (token is ConditionalAceOperatorToken) {
					var operatorToken = (ConditionalAceOperatorToken) token;
					if (operatorToken.OperatorType == ConditionalAceOperatorTokenType.Unary) {
						var unaryOperation = new ConditionalAceUnaryCondition(operatorToken);
						unaryOperation.Operand = stack.Pop();
						stack.Push(unaryOperation);
					}
					else if (operatorToken.OperatorType == ConditionalAceOperatorTokenType.Binary) {
						var binaryOperation = new ConditionalAceBinaryCondition(operatorToken);
						binaryOperation.RightOperand = stack.Pop();
						binaryOperation.LeftOperand = stack.Pop();
						stack.Push(binaryOperation);
					}
					else {
						throw new Exception(string.Format("token is ConditionalAceOperatorToken, but is of unknown OperatorType '{0}'", operatorToken.OperatorType));
					}
				}
				else {
					throw new Exception(string.Format("Unknown token type: {0}", token.GetType().Name));
				}
			}

			if (stack.Count != 1) {
				throw new Exception(string.Format("Stack contains {0} elements (it should contain 1)", stack.Count));
			}
			return (stack.Pop() as ConditionalAceCondition);
		}

		public byte[] GetApplicationData() {
			
			int paddedSize = 0;
			int binarySize = 0;
			int signatureSize = System.Runtime.InteropServices.Marshal.SizeOf(ConditionalAceToken.ApplicationDataSignature);
			
			binarySize = this.BinaryLength + signatureSize;
			
			// Must align on DWORD (4 bytes)
			paddedSize = binarySize;
			int remainder = binarySize % 4;
			if (remainder != 0) {
				paddedSize += 4 - remainder;
			}
			
			byte[] binaryApplicationData = new byte[paddedSize];
			
			// Put signature in byte array:
			byte[] signature = BitConverter.GetBytes(ConditionalAceToken.ApplicationDataSignature);
			signature.CopyTo(binaryApplicationData, 0);
			
			this.GetBinaryForm(binaryApplicationData, signature.Length);
			
			for (int i = paddedSize - (paddedSize - binarySize); i < paddedSize; i++) {
				binaryApplicationData[i] = 0;
			}
			
			return binaryApplicationData;
		}

		internal override byte[] _BinaryForm { get { return new byte[0]; } }
	}

	public class ConditionalAceUnaryCondition : ConditionalAceCondition {

		public ConditionalAceUnaryCondition(ConditionalAceOperatorToken operatorToken) : base(operatorToken) {
			if (operatorToken.OperatorType != ConditionalAceOperatorTokenType.Unary) {

				throw new Exception(string.Format("Can't create ConditionalAceUnaryCondition with non-unary operator '{0}'", operatorToken));
			}
		}

		public ConditionalAceConditionOperand Operand { get; set; }

		internal override byte[] _BinaryForm {
			get {
				int size = base.Operator.BinaryLength + this.Operand.BinaryLength;

				byte[] binaryForm = new byte[size];
				int offset = 0;
				this.Operand.GetBinaryForm(binaryForm, offset);
				offset += this.Operand.BinaryLength;

				base.Operator.GetBinaryForm(binaryForm, offset);

				return binaryForm;
			}
		}

		public override string ToString() {
			return string.Format("({0} {1})", base.Operator.ToString(), this.Operand.ToString());
		}
	}


	public class ConditionalAceBinaryCondition : ConditionalAceCondition {

		public ConditionalAceBinaryCondition(ConditionalAceOperatorToken operatorToken) : base(operatorToken) {
			if (operatorToken.OperatorType != ConditionalAceOperatorTokenType.Binary) {
				throw new Exception(string.Format("Can't create ConditionalAceBinaryCondition with non-binary operator '{0}'", operatorToken));
			}
		}

		public ConditionalAceConditionOperand LeftOperand { get; set; }
		public ConditionalAceConditionOperand RightOperand { get; set; }

		internal override byte[] _BinaryForm {
			get {
				int size = base.Operator.BinaryLength + this.LeftOperand.BinaryLength + this.RightOperand.BinaryLength;

				byte[] binaryForm = new byte[size];
				int offset = 0;
				this.LeftOperand.GetBinaryForm(binaryForm, offset);
				offset += this.LeftOperand.BinaryLength;

				this.RightOperand.GetBinaryForm(binaryForm, offset);
				offset += this.RightOperand.BinaryLength;

				base.Operator.GetBinaryForm(binaryForm, offset);

				return binaryForm;
			}
		}

		public override string ToString() {
			return string.Format("({0} {1} {2})", this.LeftOperand.ToString(), base.Operator.ToString(), this.RightOperand.ToString());
		}
	}

	public abstract class ConditionalAceToken {

		public const Int32 ApplicationDataSignature = 2020897377;

		public ConditionalAceToken(ConditionalAceTokenByteCode byteCode) {
			this.TokenByteCode = byteCode;
		}

		internal ConditionalAceTokenByteCode TokenByteCode { get; private set; }

		internal abstract byte[] _BinaryForm { get; }

		public int BinaryLength {
			get {
				return _BinaryForm.Length;
			}
		}

		public void GetBinaryForm(byte[] binaryForm, int offset) {
				_BinaryForm.CopyTo(binaryForm, offset);
		}

		internal static string GetString(byte[] binaryForm, int offset, int length, System.Text.Encoding encoding) {
			if (BitConverter.IsLittleEndian == false) {
				// Data is stored little endian. Method isn't set up to
				// handle a big endian architecture
				throw new Exception("Unsupported architecture (GetString())");
			}

			return encoding.GetString(binaryForm, offset, length);
		}

		public static List<ConditionalAceToken> GetTokens(byte[] binaryForm, int offset, int length) {

			int maxOffset = offset + length;
			List<ConditionalAceToken> tokenList = new List<ConditionalAceToken>();
			ConditionalAceTokenByteCode tokenByteCode;

			while (offset < maxOffset) {
				tokenByteCode = (ConditionalAceTokenByteCode) binaryForm[offset++];
                //Console.WriteLine("offset = {0}; maxOffset = {1}: {2}", offset - 1, maxOffset, tokenByteCode);

				switch (tokenByteCode) {
					case ConditionalAceTokenByteCode.Padding:  // Padding
						tokenList.Add(new ConditionalAcePaddingToken());
						break;

					case ConditionalAceTokenByteCode.UnicodeString:
					case ConditionalAceTokenByteCode.OctetString:
						tokenList.Add(ConditionalAceStringToken.FromBytes(binaryForm, offset, tokenByteCode));
						break;

					case ConditionalAceTokenByteCode.ResourceAttribute:
					case ConditionalAceTokenByteCode.LocalAttribute:
					case ConditionalAceTokenByteCode.DeviceAttribute:
					case ConditionalAceTokenByteCode.UserAttribute:
						tokenList.Add(ConditionalAceAttributeToken.FromBytes(binaryForm, offset, tokenByteCode));
						break;

					case ConditionalAceTokenByteCode.Composite:  // Composite
						tokenList.Add(ConditionalAceCompositeToken.FromBytes(binaryForm, offset));
						break;

					case ConditionalAceTokenByteCode.Sid:  // SID
						tokenList.Add(ConditionalAceSecurityIdentifierToken.FromBytes(binaryForm, offset));
						break;


					case ConditionalAceTokenByteCode.Exists:
					case ConditionalAceTokenByteCode.Member_of:
					case ConditionalAceTokenByteCode.Device_Member_of:
					case ConditionalAceTokenByteCode.Member_of_Any:
					case ConditionalAceTokenByteCode.Device_Member_of_Any:
					case ConditionalAceTokenByteCode.Not_Exists:
					case ConditionalAceTokenByteCode.Not_Member_of:
					case ConditionalAceTokenByteCode.Not_Device_Member_of:
					case ConditionalAceTokenByteCode.Not_Member_of_Any:
					case ConditionalAceTokenByteCode.Not_Device_Member_of_Any:
					case ConditionalAceTokenByteCode.Not:
					case ConditionalAceTokenByteCode.Equals:
					case ConditionalAceTokenByteCode.NotEquals:
					case ConditionalAceTokenByteCode.LessThan:
					case ConditionalAceTokenByteCode.LessThanOrEqualTo:
					case ConditionalAceTokenByteCode.GreaterThan:
					case ConditionalAceTokenByteCode.GreaterThanOrEqualTo:
					case ConditionalAceTokenByteCode.Contains:
					case ConditionalAceTokenByteCode.AnyOf:
					case ConditionalAceTokenByteCode.NotContains:
					case ConditionalAceTokenByteCode.NotAnyOf:
					case ConditionalAceTokenByteCode.And:
					case ConditionalAceTokenByteCode.Or:
						tokenList.Add(new ConditionalAceOperatorToken(tokenByteCode));
						break;

					default:
						throw new Exception(string.Format("Unknown token byte code: 0x{0:x2}", (byte)tokenByteCode));
				}

				offset += tokenList.Last().BinaryLength - 1;  // -1 b/c offset was already incremented
			}
			return tokenList;
		}
	}

	public class ConditionalAcePaddingToken : ConditionalAceLiteralToken {

		public ConditionalAcePaddingToken() : base(ConditionalAceTokenByteCode.Padding) {}

		internal override byte[] _BinaryForm {
			get {
				byte[] binaryForm = new byte[1];
				binaryForm[0] = (byte) base.TokenByteCode;
				return binaryForm;
			}
		}

		public override string ToString() { return string.Empty; }
	}

	public abstract class ConditionalAceLiteralToken : ConditionalAceToken {

		internal ConditionalAceLiteralToken(ConditionalAceTokenByteCode byteCode) : base(byteCode) {}

		internal override byte[] _BinaryForm { get { return new byte[0]; } }
	}

	public class ConditionalAceAttributeToken : ConditionalAceLiteralToken {

		public ConditionalAceAttributeToken(ConditionalAceTokenByteCode attributeType, string attributeName) : base(attributeType) {
			switch (attributeType) {
				case ConditionalAceTokenByteCode.UserAttribute:
				case ConditionalAceTokenByteCode.DeviceAttribute:
				case ConditionalAceTokenByteCode.LocalAttribute:
				case ConditionalAceTokenByteCode.ResourceAttribute:
					// Do nothing
					break;

				default:
					throw new Exception(string.Format("TokenByteCode '{0}' is not an attribute type", attributeType));
			}

			// Create a unicode string token:
			this.UnicodeStringToken = new ConditionalAceStringToken(attributeName, attributeType, true);
		}

		internal ConditionalAceStringToken UnicodeStringToken { get; private set; }

		public string AttributeName { 
			get {
				return this.UnicodeStringToken.StringValue;
			}
			set {
				this.UnicodeStringToken.StringValue = value;
			}
		}

		public override string ToString() {
			return string.Format("@{0}.{1}", base.TokenByteCode.ToString().Replace("Attribute","").ToUpper(), this.AttributeName);
		}

		public static ConditionalAceAttributeToken FromBytes(byte[] binaryForm, int offset, ConditionalAceTokenByteCode tokenType) {

			int length = BitConverter.ToInt32(binaryForm, offset);

			if (length >= (binaryForm.Length - offset)) {
				throw new Exception("Unable to create ConditionalAceStringToken from byte array; length is too long");
			}

			string attributeName = Encoding.Unicode.GetString(binaryForm, offset + 4, length);
			return new ConditionalAceAttributeToken(tokenType, attributeName);
		}

		internal override byte[] _BinaryForm {
			get {
				return this.UnicodeStringToken._BinaryForm;
			}
		}
	}

	public class ConditionalAceStringToken : ConditionalAceLiteralToken {

		public ConditionalAceStringToken() : this(string.Empty) {}

		public ConditionalAceStringToken(string stringValue) : this(string.Empty, ConditionalAceTokenByteCode.UnicodeString) {}

		public ConditionalAceStringToken(string stringValue, ConditionalAceTokenByteCode tokenType) : this(stringValue, tokenType, false) { }

		internal ConditionalAceStringToken(string stringValue, ConditionalAceTokenByteCode tokenType, bool allowAttributeType) : base(tokenType) {
			// Hidden constructor that allows token types other than Unicode and Octet strings
			this.Encoding = GetEncodingFromByteCode(tokenType, allowAttributeType);
			this.StringValue = stringValue;
		}

		private static Encoding GetEncodingFromByteCode(ConditionalAceTokenByteCode tokenType, bool allowAttributeType) {
			switch (tokenType) {
				case ConditionalAceTokenByteCode.UnicodeString:
					return Encoding.Unicode;

				case ConditionalAceTokenByteCode.ResourceAttribute:
				case ConditionalAceTokenByteCode.UserAttribute:
				case ConditionalAceTokenByteCode.LocalAttribute:
				case ConditionalAceTokenByteCode.DeviceAttribute:
					if (allowAttributeType) {
						return Encoding.Unicode;
					}
					else {
						goto default;
					}

				case ConditionalAceTokenByteCode.OctetString:
					return Encoding.UTF8;

				default:
					throw new Exception(string.Format("Unable to determine encoding from byte code '{0}", tokenType));
			}
		}

		public Encoding Encoding { get; private set; }
		
		public string StringValue { get; set; }

		public static ConditionalAceStringToken FromBytes(byte[] binaryForm, int offset, ConditionalAceTokenByteCode tokenType) {

			int length = BitConverter.ToInt32(binaryForm, offset);

			if (length >= (binaryForm.Length - offset)) {
				throw new Exception("Unable to create ConditionalAceStringToken from byte array; length is too long");
			}

			var stringToken = new ConditionalAceStringToken(string.Empty, tokenType);
			stringToken.StringValue = stringToken.Encoding.GetString(binaryForm, offset + 4, length);

			return stringToken;
		}

		public override string ToString() {
			return string.Format("\"{0}\"", this.StringValue);
		}

		internal override byte[] _BinaryForm {
			get {
				byte[] binaryForm;
				int contentSize = 1;  // Token byte code
				contentSize += 4;     // DWORD for size of string

				byte[] stringBytes = this.Encoding.GetBytes(this.StringValue);
				contentSize += stringBytes.Length;

				binaryForm = new byte[contentSize];
				binaryForm[0] = (byte) base.TokenByteCode;
				BitConverter.GetBytes(stringBytes.Length).CopyTo(binaryForm, 1);

				// Copy binary form of string:
				stringBytes.CopyTo(binaryForm, 5);

				return binaryForm;
			}
		}
	}

	public class ConditionalAceCompositeToken : ConditionalAceLiteralToken {

		public ConditionalAceCompositeToken() : base(ConditionalAceTokenByteCode.Composite) {
			this.Tokens = new List<ConditionalAceToken>();
		}

		public static ConditionalAceCompositeToken FromBytes(byte[] binaryForm, int offset) {

			var returnToken = new ConditionalAceCompositeToken();

			int compositeLength = BitConverter.ToInt32(binaryForm, offset);
			
			foreach (var currentToken in GetTokens(binaryForm, offset + 4, compositeLength)) {
				returnToken.Tokens.Add(currentToken);
			}

			return returnToken;
		}

		public List<ConditionalAceToken> Tokens { get; set; }

		internal override byte[] _BinaryForm {
			get {

				byte[] binaryForm;
				int contentSize = 1;  // Token byte code
				contentSize += 4;     // DWORD for size of list

				if (this.Tokens == null) {
					throw new Exception("No Tokens!");
				}

				int listLength = 0;
				foreach (var token in this.Tokens) {
					listLength += token.BinaryLength;
				}
				contentSize += listLength;

				binaryForm = new byte[contentSize];
				binaryForm[0] = (byte) base.TokenByteCode;
				BitConverter.GetBytes(listLength).CopyTo(binaryForm, 1);

				int index = 5;
				foreach (var token in this.Tokens) {
					token.GetBinaryForm(binaryForm, index);
					index += token.BinaryLength;
				}
				return binaryForm;
			}
		}

		public override string ToString() {
			return string.Format("({0})", string.Join(", ", this.Tokens));
		}
	}

	public class ConditionalAceSecurityIdentifierToken : ConditionalAceLiteralToken {

		public ConditionalAceSecurityIdentifierToken(SecurityIdentifier sid) : base(ConditionalAceTokenByteCode.Sid) {
			this.SecurityIdentifier = sid;
		}

		public static ConditionalAceSecurityIdentifierToken FromBytes(byte[] binaryForm, int offset) {
			int sidLength = BitConverter.ToInt32(binaryForm, offset);
			byte[] sidBinaryForm = new byte[sidLength];

			Array.Copy(binaryForm, offset + 4, sidBinaryForm, 0, sidLength);
			return new ConditionalAceSecurityIdentifierToken(new SecurityIdentifier(sidBinaryForm, 0));
		}

		public SecurityIdentifier SecurityIdentifier { get; private set; }

        // This will be PacPrincipal in final code...didn't want to deal with reference right now
        public IdentityReference TranslatedAccount { 
            get {
                return this.SecurityIdentifier.Translate(typeof(NTAccount));
            }
        }

		internal override byte[] _BinaryForm {
			get {

				byte[] binaryForm;
				int contentSize = 1;
				contentSize += 4;  // DWORD for SID size

				if (this.SecurityIdentifier != null) {
					contentSize += this.SecurityIdentifier.BinaryLength;
				}
				else {
					throw new Exception("No SID");
				}

				binaryForm = new byte[contentSize];
				binaryForm[0] = (byte) base.TokenByteCode;
				BitConverter.GetBytes(this.SecurityIdentifier.BinaryLength).CopyTo(binaryForm, 1);
				this.SecurityIdentifier.GetBinaryForm(binaryForm, 5);
				return binaryForm;
			}
		}

		public override string ToString() {
            
            IdentityReference translatedAccount = this.TranslatedAccount;
            if (translatedAccount is SecurityIdentifier) {
                // Account couldn't be translated
                return string.Format("SID[{0}]", translatedAccount.ToString());
            }
            else {
                return translatedAccount.ToString();
            }
		}
	}

	public class ConditionalAceOperatorToken : ConditionalAceToken {

		public ConditionalAceOperatorToken(ConditionalAceTokenByteCode byteCode) : base(byteCode) {

			switch ((ConditionalAceTokenByteCode) byteCode) {

				case ConditionalAceTokenByteCode.Exists:
				case ConditionalAceTokenByteCode.Member_of:
				case ConditionalAceTokenByteCode.Device_Member_of:
				case ConditionalAceTokenByteCode.Member_of_Any:
				case ConditionalAceTokenByteCode.Device_Member_of_Any:
				case ConditionalAceTokenByteCode.Not_Exists:
				case ConditionalAceTokenByteCode.Not_Member_of:
				case ConditionalAceTokenByteCode.Not_Device_Member_of:
				case ConditionalAceTokenByteCode.Not_Member_of_Any:
				case ConditionalAceTokenByteCode.Not_Device_Member_of_Any:
				case ConditionalAceTokenByteCode.Not:
					this.OperatorType = ConditionalAceOperatorTokenType.Unary;
					break;

				case ConditionalAceTokenByteCode.Equals:
				case ConditionalAceTokenByteCode.NotEquals:
				case ConditionalAceTokenByteCode.LessThan:
				case ConditionalAceTokenByteCode.LessThanOrEqualTo:
				case ConditionalAceTokenByteCode.GreaterThan:
				case ConditionalAceTokenByteCode.GreaterThanOrEqualTo:
				case ConditionalAceTokenByteCode.Contains:
				case ConditionalAceTokenByteCode.AnyOf:
				case ConditionalAceTokenByteCode.NotContains:
				case ConditionalAceTokenByteCode.NotAnyOf:
				case ConditionalAceTokenByteCode.And:
				case ConditionalAceTokenByteCode.Or:
					this.OperatorType = ConditionalAceOperatorTokenType.Binary;
					break;

				default:
					//throw new Exception(string.Format("Unknown operator byte code: 0x{0:x2}", byteCode));
					throw new Exception(string.Format("Invalid operator byte code: {0}", byteCode));
			}

		}

		internal ConditionalAceOperatorTokenType OperatorType { get; private set; }

		internal override byte[] _BinaryForm {
			get {
				byte[] binaryForm = new byte[1];
				binaryForm[0] = (byte) base.TokenByteCode;
				return binaryForm;
			}
		}

		public override string ToString() {

			string returnString;
			switch (base.TokenByteCode) {

				case ConditionalAceTokenByteCode.And:
				case ConditionalAceTokenByteCode.Or:
				case ConditionalAceTokenByteCode.Not:
				case ConditionalAceTokenByteCode.Contains:
				case ConditionalAceTokenByteCode.NotContains:
					returnString = "-" + base.TokenByteCode.ToString().ToLower();
					break;

				case ConditionalAceTokenByteCode.AnyOf:
				case ConditionalAceTokenByteCode.NotAnyOf:
					returnString = "-" + base.TokenByteCode.ToString().ToLower().Replace("anyof", "in");
					break;

				case ConditionalAceTokenByteCode.Equals:
					returnString = "-eq";
					break;

				case ConditionalAceTokenByteCode.NotEquals:
					returnString = "-ne";
					break;

				case ConditionalAceTokenByteCode.LessThan:
					returnString = "-lt";
					break;

				case ConditionalAceTokenByteCode.LessThanOrEqualTo:
					returnString = "-le";
					break;

				case ConditionalAceTokenByteCode.GreaterThan:
					returnString = "-gt";
					break;

				case ConditionalAceTokenByteCode.GreaterThanOrEqualTo:
					returnString = "-ge";
					break;

				case ConditionalAceTokenByteCode.Member_of_Any:
					// Considering changing this to show that a user is a member of a group. If so, will need to 
                    // handle other operators (both user and device)...
					//returnString = "@USER -in";

                    returnString = base.TokenByteCode.ToString();
					break;

				default:
					returnString = base.TokenByteCode.ToString();
					break;
			}

			return returnString;
		}
	}
}