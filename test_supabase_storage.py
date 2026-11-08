
import os
from dotenv import load_dotenv
from supabase import create_client

load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_SECRET_KEY")

if not url or not key:
    raise ValueError("Supabase environment variables missing!")

supabase = create_client(url, key)

bucket = "trustvault-documents"
path = "connection-test/test.txt"
content = b"TrustVault Supabase Storage Test"

try:
    # Upload
    supabase.storage.from_(bucket).upload(
        path,
        content,
        file_options={
            "content-type": "text/plain",
            "upsert": "true"
        }
    )
    print("Upload successful!")

    # Download
    downloaded = supabase.storage.from_(bucket).download(path)

    if downloaded == content:
        print("Download successful!")
    else:
        raise ValueError("Downloaded content does not match!")

    # Delete
    supabase.storage.from_(bucket).remove([path])
    print("Delete successful!")

    print("\nAll Supabase Storage tests passed!")

except Exception as e:
    print("Storage test failed:", e)
