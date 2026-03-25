import asyncio
import os
import sys

# Add Medusa to path
sys.path.append(r"c:\Users\ajst1\Downloads\Medusa")

from medusa.engine.modules.ai.chat import LunaChat

async def test_luna_fs():
    print("Initializing LunaChat...")
    chat = LunaChat()
    
    test_file = "luna_test_write.txt"
    test_content = "This is a test write from Luna's neural engine."
    
    # Simulate an LLM response with macros
    luna_raw_response = f"I've written a special note for you, David. [[WRITE: {test_file} | {test_content}]] Check it out."
    
    print(f"Mocking Luna response: {luna_raw_response}")
    
    # Process macros
    clean_resp = await chat._handle_system_macros(luna_raw_response)
    
    print(f"Clean response for David: {clean_resp}")
    
    # Verify file
    if os.path.exists(test_file):
        with open(test_file, "r") as f:
            read_back = f.read()
        if read_back == test_content:
            print("SUCCESS: File written correctly by macro handler.")
        else:
            print(f"FAILURE: File content mismatch. Got: {read_back}")
        os.remove(test_file)
    else:
        print("FAILURE: File was not created.")

if __name__ == "__main__":
    asyncio.run(test_luna_fs())
