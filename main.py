import os
import logging
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from telegram import Update, Bot
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext

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
def start(update: Update, context: CallbackContext):
    update.message.reply_text(
        "Welcome to the File Encryption Bot! 🛡️\n\n"
        "Send me a file, and I will encrypt it for you. 🔒\n"
        "Send an encrypted file, and I will decrypt it for you. 🔓"
    )

# Handle incoming documents (files)
def handle_file(update: Update, context: CallbackContext):
    user = update.message.from_user
    logger.info(f"User {user.first_name} sent a file.")

    # Download the file
    file = update.message.document.get_file()
    input_file = os.path.join(TEMP_DIR, file.file_id)
    file.download(input_file)

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
    update.message.reply_text(f"Your file has been {action}. 🔒")
    update.message.reply_document(document=open(output_file, "rb"))

    # Delete temporary files
    delete_files([input_file, output_file])

# Error handler
def error(update: Update, context: CallbackContext):
    logger.warning(f"Update {update} caused error {context.error}")

# Main function to start the bot
def main():
    # Replace 'YOUR_BOT_TOKEN' with your actual Telegram bot token
    updater = Updater("7648055696:AAHm0jhbjOgzTtrxaFODLgkQ0C-WDwN81h8", use_context=True)

    # Get the dispatcher to register handlers
    dp = updater.dispatcher

    # Register command and message handlers
    dp.add_handler(CommandHandler("start", start))
    dp.add_handler(MessageHandler(Filters.document, handle_file))

    # Register error handler
    dp.add_error_handler(error)

    # Start the bot
    updater.start_polling()
    updater.idle()

if __name__ == "__main__":
    main()
