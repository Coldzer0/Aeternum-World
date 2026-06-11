# NW Capture Tools



## How to use

First install the requirements
```
pip install -r requirements.txt
```


To capture DTLS Packets and HTTPS
```
python nw_capture.py --target "C:\SteamLibrary\steamapps\common\New World\Bin64\NewWorld.exe" --timeout 600000 --session session_name_here
```

To Decode the ledger.bin file

```
python decode_dtls_ledger.py path_2_ledger.bin --out decoded_session.jsonl
```

Check our [Capture TODO List](CAPTURES_TODO.MD)

## With ❤️ From Home.
