

from PIL import Image, ImageDraw, ImageFont
import math
from PIL import ImageEnhance, ImageFilter
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import serialization
import datetime
import os

class DocumentSigner:
    def __init__(self):
        # Generate key pair if not exists
        if not os.path.exists('private_key.pem'):
            self.generate_keys()
        self.load_keys()

    def generate_keys(self):
        """Generate public and private keys"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Save private key
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key
        public_key = private_key.public_key()
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

    def load_keys(self):
        """Load keys from files"""
        with open("private_key.pem", "rb") as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        
        with open("public_key.pem", "rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read())

    def sign_document(self, image_path):
        """Create digital signature for the document"""
        with open(image_path, 'rb') as f:
            data = f.read()
        
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, image_path, signature):
        """Verify the document's signature"""
        with open(image_path, 'rb') as f:
            data = f.read()
        
        try:
            self.public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except:
            return False

def create_signed_watermarked_document(image_path, output_path, watermark_text="CONFIDENTIAL", opacity=35):
    """
    Add both digital signature and watermark to the document
    """
    try:
        # Create digital signature
        signer = DocumentSigner()
        signature = signer.sign_document(image_path)
        
        # Generate signature timestamp
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create watermark with signature information
        with Image.open(image_path) as img:
            if img.mode != 'RGBA':
                img = img.convert('RGBA')
            
            # Create watermark layer
            watermark = Image.new('RGBA', img.size, (255, 255, 255, 0))
            draw = ImageDraw.Draw(watermark)
            
            # Try to load a nice font
            try:
                main_font = ImageFont.truetype("arial.ttf", 70)
                sig_font = ImageFont.truetype("arial.ttf", 20)
            except:
                main_font = ImageFont.load_default()
                sig_font = ImageFont.load_default()
            
            # Add watermark
            diagonal = math.sqrt(img.width**2 + img.height**2)
            spacing = int(diagonal // 3)
            angle = 30
            
            # Add diagonal watermarks
            for y in range(-img.height, img.height*2, spacing):
                for x in range(-img.width, img.width*2, spacing):
                    text_image = Image.new('RGBA', 
                                         (int(draw.textlength(watermark_text, font=main_font)*1.2), 
                                          int(main_font.size*2)), 
                                         (255, 255, 255, 0))
                    text_draw = ImageDraw.Draw(text_image)
                    
                    # Add shadow and main text
                    text_draw.text((3, 3), watermark_text, font=main_font, fill=(0, 0, 0, opacity//3))
                    text_draw.text((0, 0), watermark_text, font=main_font, fill=(220, 220, 220, opacity))
                    
                    rotated = text_image.rotate(angle, expand=True, resample=Image.Resampling.BICUBIC)
                    watermark.paste(rotated, (x, y), rotated)
            
            # Add signature information at bottom
            sig_text = f"Digitally Signed | {timestamp}"
            sig_hash = hashlib.sha256(signature).hexdigest()[:20]  # First 20 chars of signature hash
            
            # Create signature box
            box_height = 60
            box = Image.new('RGBA', (img.width, box_height), (245, 245, 245, 200))
            box_draw = ImageDraw.Draw(box)
            
            # Add signature information
            box_draw.text((10, 10), sig_text, font=sig_font, fill=(0, 0, 0, 255))
            box_draw.text((10, 30), f"Signature: {sig_hash}...", font=sig_font, fill=(0, 0, 0, 255))
            
            # Combine all layers
            watermark.paste(box, (0, img.height - box_height), box)
            result = Image.alpha_composite(img, watermark)
            
            # Save the result
            result.convert('RGB').save(output_path, 'JPEG', quality=95)
            
            # Save signature separately
            with open(f"{output_path}.sig", 'wb') as f:
                f.write(signature)
            
            print(f"Document signed and watermarked successfully. Saved to {output_path}")
            print(f"Signature saved to {output_path}.sig")
            
            # Verify the signature
            if signer.verify_signature(output_path, signature):
                print("✓ Signature verification successful")
            else:
                print("⚠ Signature verification failed")
            
    except Exception as e:
        print(f"An error occurred: {str(e)}")

# Example usage
if __name__ == "__main__":
    input_path = r"C:\Users\P NITISH\OneDrive\Desktop\git\BhagavadGita\queue\myvenv\abc.jpg"
    output_path = "signed_watermarked_certificate.jpg"
    create_signed_watermarked_document(
        image_path=input_path,
        output_path=output_path,
        watermark_text="★ OFFICIAL DOCUMENT ★",
        opacity=35
    )