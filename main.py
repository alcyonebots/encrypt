import os
import logging
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Encryption settings
KEY = os.urandom(32)  # 256-bit key
IV = os.urandom(16)   # 128-bit IV

# Directory to store temporary files
TEMP_DIR = "temp_files"
os.makedirs(TEMP_DIR, exist_ok=True)

# Encrypt a file using AES-256 in CBC mode
def encrypt_file(input_file, output_file):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_file, "rb") as f:
        with open(output_file, "wb") as f_out:
            f_out.write(IV)  # Write the IV to the output file
            while chunk := f.read(4096):
                padded_data = padder.update(chunk)
                f_out.write(encryptor.update(padded_data))
            padded_data = padder.finalize()
            f_out.write(encryptor.update(padded_data))
            f_out.write(encryptor.finalize())

# Decrypt a file using AES-256 in CBC mode
def decrypt_file(input_file, output_file):
import os
import logging
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# Enable logging
logging.basicConfig(
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s", level=logging.INFO
)
logger = logging.getLogger(__name__)

# Encryption settings
KEY = os.urandom(32)  # 256-bit key
IV = os.urandom(16)   # 128-bit IV

# Directory to store temporary files
TEMP_DIR = "temp_files"
os.makedirs(TEMP_DIR, exist_ok=True)

# Encrypt a file using AES-256 in CBC mode
def encrypt_file(input_file, output_file):
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()

    with open(input_file, "rb") as f:
        with open(output_file, "wb") as f_out:
            f_out.write(IV)  # Write the IV to the output file
            while chunk := f.read(4096):
                padded_data = padder.update(chunk)
                f_out.write(encryptor.update(padded_data))
            padded_data = padder.finalize()
            f_out.write(encryptor.update(padded_data))
            f_out.write(encryptor.finalize())

# Decrypt a file using AES-256 in CBC mode
def decrypt_file(input_file, output_file):
    with open(input_file, "rb") as f:
        iv = f.read(16)  # Read the IV from the input file
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        with open(output_file, "wb") as f_out:
            while chunk := f.read(4096):
                decrypted_data = decryptor.update(chunk)
                f_out.write(unpadder.update(decrypted_data))
            decrypted_data = decryptor.finalize()
            f_out.write(unpadder.update(decrypted_data))
            f_out.write(unpadder.finalize())

# Delete files from the server after processing
def delete_files(file_paths):
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Deleted: {file_path}")

# Command handler for /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Welcome to the File Encryption Bot! 🛡️\n\n"
        "Send me a file, and I will encrypt it for you. 🔒\n"
        "Send an encrypted file, and I will decrypt it for you. 🔓"
    )

# Handle incoming documents (files)
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user
    logger.info(f"User {user.first_name} sent a file.")

    # Download the file
    file = await update.message.document.get_file()
    input_file = os.path.join(TEMP_DIR, file.file_id)
    await file.download_to_drive(input_file)

    # Determine if the file is encrypted (based on file extension or user input)
    if update.message.caption and "decrypt" in update.message.caption.lower():
        # Decrypt the file
        output_file = os.path.join(TEMP_DIR, f"decrypted_{file.file_id}")
        decrypt_file(input_file, output_file)
        action = "decrypted"
    else:
        # Encrypt the file
        output_file = os.path.join(TEMP_DIR, f"encrypted_{file.file_id}.enc")
        encrypt_file(input_file, output_file)
        action = "encrypted"

    # Send the processed file back to the user
    await update.message.reply_text(f"Your file has been {action}. 🔒")
    await update.message.reply_document(document=open(output_file, "rb"))

    # Delete temporary files
    delete_files([input_file, output_file])

# Error handler
async def error(update: Update, context: ContextTypes.DEFAULT_TYPE):
    logger.warning(f"Update {update} caused error {context.error}")

# Main function to start the bot
def main():
    # Replace '7648055696:AAHm0jhbjOgzTtrxaFODLgkQ0C-WDwN81h8' with your actual Telegram bot token
    application = Application.builder().token("YOUR_BOT_TOKEN").build()

    # Register command and message handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.Document.ALL, handle_file))

    # Register error handler
    application.add_error_handler(error)

    # Start the bot
    application.run_polling()

if __name__ == "__main__":
    main()￼Enter    with open(input_file, "rb") as f:
        iv = f.read(16)  # Read the IV from the input file
        cipher = Cipher(algorithms.AES(KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

        with open(output_file, "wb") as f_out:
            while chunk := f.read(4096):
                decrypted_data = decryptor.update(chunk)
                f_out.write(unpadder.update(decrypted_data))
            decrypted_data = decryptor.finalize()
            f_out.write(unpadder.update(decrypted_data))
            f_out.write(unpadder.finalize())

# Delete files from the server after processing
def delete_files(file_paths):
    for file_path in file_paths:
        if os.path.exists(file_path):
            os.remove(file_path)
            logger.info(f"Deleted: {file_path}")

# Command handler for /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Welcome to the File Encryption Bot! 🛡️\n\n"
        "Send me a file, and I will encrypt it for you. 🔒\n"
  "Send an encrypted file, and I will decrypt it for you. 🔓"
    )

# Handle incoming documents (files)
async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.message.from_user
    logger.info(f"User {user.first_name} sent a file.")

    # Download the file
    file = await update.message.document.get_file()
    input_file = os.path.join(TEMP_DIR, file.file_id)
    await file.download_to_drive(input_file)

    # Determine if the file is encrypted (based on file extension or user input)
    if update.message.caption and "decrypt" in update.message.caption.lower():
        # Decrypt the file
        output_file = os.path.join(TEMP_DIR, f"decrypted_{file.file_id}")
        decrypt_file(input_file, output_file)
        action = "decrypted"
    else:
        # Encrypt the file
        output_file = os.path.join(TEMP_DIR, f"encrypted_{file.file_id}.enc")
        encrypt_file(input_file, output_file)
        action = "encrypted"

    # Send the processed file back to the user
