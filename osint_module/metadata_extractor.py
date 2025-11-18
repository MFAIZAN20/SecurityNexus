#!/usr/bin/env python3
"""
Metadata Extractor - OSINT Module
Extracts metadata from documents (PDF, images, Office files)
Reveals sensitive information like author names, software, GPS coordinates
"""

import sys
import os
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import PyPDF2
import requests
from io import BytesIO

class MetadataExtractor:
    def __init__(self):
        self.metadata = {}
    
    def extract_image_metadata(self, image_path):
        """Extract EXIF data from images"""
        print(f"\n[*] Extracting metadata from image: {image_path}")
        
        try:
            image = Image.open(image_path)
            exif_data = image._getexif()
            
            if not exif_data:
                print("[-] No EXIF data found")
                return {}
            
            metadata = {}
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                metadata[tag] = value
            
            # Extract GPS data if present
            if 'GPSInfo' in metadata:
                gps_info = {}
                for key in metadata['GPSInfo'].keys():
                    name = GPSTAGS.get(key, key)
                    gps_info[name] = metadata['GPSInfo'][key]
                metadata['GPSInfo'] = gps_info
            
            self.print_image_metadata(metadata)
            return metadata
            
        except Exception as e:
            print(f"[-] Error: {e}")
            return {}
    
    def extract_pdf_metadata(self, pdf_path):
        """Extract metadata from PDF files"""
        print(f"\n[*] Extracting metadata from PDF: {pdf_path}")
        
        try:
            with open(pdf_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                metadata = pdf_reader.metadata
                
                if metadata:
                    self.print_pdf_metadata(metadata)
                    return dict(metadata)
                else:
                    print("[-] No metadata found")
                    return {}
                    
        except Exception as e:
            print(f"[-] Error: {e}")
            return {}
    
    def download_and_extract(self, url):
        """Download file from URL and extract metadata"""
        print(f"\n[*] Downloading file from: {url}")
        
        try:
            response = requests.get(url, timeout=10)
            file_data = BytesIO(response.content)
            
            # Determine file type
            if url.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                return self.extract_image_metadata_from_bytes(file_data)
            elif url.lower().endswith('.pdf'):
                return self.extract_pdf_metadata_from_bytes(file_data)
            else:
                print("[-] Unsupported file type")
                return {}
                
        except Exception as e:
            print(f"[-] Error: {e}")
            return {}
    
    def extract_image_metadata_from_bytes(self, image_data):
        """Extract metadata from image bytes"""
        try:
            image = Image.open(image_data)
            exif_data = image._getexif()
            
            if exif_data:
                metadata = {}
                for tag_id, value in exif_data.items():
                    tag = TAGS.get(tag_id, tag_id)
                    metadata[tag] = value
                
                self.print_image_metadata(metadata)
                return metadata
            else:
                print("[-] No EXIF data found")
                return {}
                
        except Exception as e:
            print(f"[-] Error: {e}")
            return {}
    
    def extract_pdf_metadata_from_bytes(self, pdf_data):
        """Extract metadata from PDF bytes"""
        try:
            pdf_reader = PyPDF2.PdfReader(pdf_data)
            metadata = pdf_reader.metadata
            
            if metadata:
                self.print_pdf_metadata(metadata)
                return dict(metadata)
            else:
                print("[-] No metadata found")
                return {}
                
        except Exception as e:
            print(f"[-] Error: {e}")
            return {}
    
    def print_image_metadata(self, metadata):
        """Print image metadata in organized format"""
        print("\n" + "=" * 60)
        print("IMAGE METADATA")
        print("=" * 60)
        
        important_tags = ['Make', 'Model', 'DateTime', 'Software', 'GPSInfo', 
                         'Artist', 'Copyright', 'DateTimeOriginal']
        
        for tag in important_tags:
            if tag in metadata:
                print(f"{tag:20s}: {metadata[tag]}")
        
        # Show GPS coordinates if available
        if 'GPSInfo' in metadata:
            gps = metadata['GPSInfo']
            print("\n🌍 GPS LOCATION FOUND!")
            for key, value in gps.items():
                print(f"  {key}: {value}")
        
        print("\nAll Tags:")
        for tag, value in metadata.items():
            if tag not in important_tags:
                print(f"  {tag}: {str(value)[:100]}")
        
        print("=" * 60)
    
    def print_pdf_metadata(self, metadata):
        """Print PDF metadata in organized format"""
        print("\n" + "=" * 60)
        print("PDF METADATA")
        print("=" * 60)
        
        keys = ['/Title', '/Author', '/Subject', '/Creator', '/Producer', 
                '/CreationDate', '/ModDate', '/Keywords']
        
        for key in keys:
            if key in metadata:
                print(f"{key[1:]:15s}: {metadata[key]}")
        
        print("\nAll Metadata:")
        for key, value in metadata.items():
            if key not in keys:
                print(f"  {key}: {value}")
        
        print("=" * 60)

def main():
    if len(sys.argv) < 2:
        print("Usage: python metadata_extractor.py <file_path_or_url>")
        print("\nExamples:")
        print("  python metadata_extractor.py image.jpg")
        print("  python metadata_extractor.py document.pdf")
        print("  python metadata_extractor.py http://example.com/photo.jpg")
        sys.exit(1)
    
    target = sys.argv[1]
    extractor = MetadataExtractor()
    
    print("=" * 60)
    print("METADATA EXTRACTOR - OSINT MODULE")
    print("=" * 60)
    
    if target.startswith('http'):
        extractor.download_and_extract(target)
    elif target.lower().endswith(('.jpg', '.jpeg', '.png', '.gif', '.tiff')):
        extractor.extract_image_metadata(target)
    elif target.lower().endswith('.pdf'):
        extractor.extract_pdf_metadata(target)
    else:
        print("[-] Unsupported file type")
        print("[!] Supported: JPG, PNG, GIF, TIFF, PDF")

if __name__ == "__main__":
    main()
