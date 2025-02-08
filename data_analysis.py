from collections import Counter
import math
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Provided data
data = '3=U³\\¬¶6|cò\\u000fã£Ü\\u001bn>]UãÊOM³YWl®cÕ\\u0017«ÔñqZ­ÓZÖø\\u005cæ\\u0017ÙGµZ.ôSv²­5\\u001f;ÌÍ¸Õ\'Ö<\\u001eYã.ËôðâøxãµtøªÓ3/VÍÆµrÜfÚczlzjÎvfñfÎÔO\\u00177iËG§tÍ£=ðÙ\\u0017ì±º+¼=êqÇV\\u005cG«ig\']+>geµÜñ\\u001e¶±§ÊÚx|<Í¸|¥ìáÚ.é\\u001bn£³¦]véeô<y¸ãÉã\\u001dò>Ö\\u001e¼Æv\'§êÌvtn6Ó¥³læ:µl\'>jélOfÇ7ÉkÌWÔ\\u001fSÕå\'§\\u001e\\u001fÉ®\\u001b§\\u001bnáx;Åô¥¶gu¦­ÊÍcÓÖÑ©¹ð¶KêÊ>\\u001b;9«ª|K¹\\u001eÜ£;.¶ÅWðø´Ü£Õæxs\\u005c®\\u005cìÌuÑÓimn²\\u001f6Ö\\u005c]VÓ¬êÆôðkcm\\u005cÚ¦|iv\\u001døUOK³.>xm6vf¹en²vMñ.OSkS:sM¶´\\u001f<;ð;\\u001e[q;67Myj]VÚcz²µM§Å³±¬O+òtm3­¦©ÓGn9y<ÇZ;\\u001eÅÚ>ÑÓØ²¹\\u001eÚY/Gãð³\\u001by£zÒÎNµxø\\u005c­Uám\\u001eÕVÎº67.z¼rÜc¹l³ÒñãNÎ³.Çfº9ñâ®l±¶<¶GÙ\\u0017§isêÚ¦øt«¥/él7:Õ¸ñ5>lñ[3æØ|SnGÑµ:>â;Ôj>-<WGN|¥W5uSã©mZømÇ3­S[¥v+m²¼VUìrÕxãYÙMWìc>3ÖØø¬Õ+Ó\\u001bmZÙÃ\\u001dØÍc«9ñæVËÌW<ÕY³:êqéiGÓ\\u005cÜéÖZgSÙNéÌnÌ=qø®ÃÓ6^<\\u0017ÍK[¥å\\u001dæÔWSs:®jvÊ^j«:ÍGñSåÑ[\\u005cÕ^\\u001b^¦Ú\\u000fÇrÇSÚ´yqì\\u001dã´yÉµ+>^j]Ysé¼ä;£­ZÇzrãV/ÅÓNvM«Ëi].§±;:ñ6Í¬ô-ºÅò±WÌ^Åy:Nvè­\\u000f¼cÖ5^ª\\u001f-ÖY=KñGÓ-Õ´ØUnÑ¶ªòÔôr¼<«.W5åm¥|Ñãª>fòØ7âñM§9^\\u000f^Åã±|eêÑÓr;¬ôV[SÇtÇ5znµ:7Mnq\\u001f6|ÆÍæK¹xã¸]+³NÇ£áñcÙÆìÊ[yK¼Nãx;¶[ÙÌkâ³\\u001eÅÜ´]-[Îr­Sò\\u001f\'>Ã|:mÆ|²ÉØ«£Ü£¶´Ír§3Ç<¶xñÊ­¦/âê<ôVµÒ/Mu+òØ§ªyj¹KÕfná|\\u001e­t\\u001flkÅkzNôÚtÌÔêjøÃËVu´uÌÙ|¼èêèÜ´mé¦«£ºqì¸¹+ÖèÜG\\u000fÜèË\\u001b\\u001bºxvÑg´OxËÒ\\u001f<[MÚô¥zÑ/âÖÑ­MæU­Y|5µ6¶xÓ©\\u001e³â®ä|Zg/á§rW©§\\u005cÙØ|ªn-Õª>MÇÑ/ªµtÎr¶Ø\\u001fâò[Ô\\u001f­iÇä³­´­µÖÌn¬mø3s3|jå¼É§\\u001bu¥ø©Oz<7|ÃÓf®\\u001bø\\u001bê3g.Ó±.¼eueô©ñg\\u001dÜ±ÚjWÆ7ry-ê²/Ìê+ÜÔ\\u001fìf[ðÍSåØ¼Ü±åeéWjOÃOÒÊ7è]Æ6­ÕØº6s;ÃñGË±éMãKºZæÚ\\u001e¹GêU\\u001f|èrv¸vqÖVô9nnÆè\\u001fÅ\\u001fKºµ¬º\\u001eµð/KW9ÙjÎU6ìÉ\\u001f\\u001eÕG;èÜi¼\\u001e^ávÃ¹£=¥3Ü3ktytºKÎòtÓ\\u000fº:^-µÑåfµYváòONO-ÙUµÆË3µ±¶©n<§ò'

def analyze_data(data):
    frequency = Counter(data)
    total_chars = sum(frequency.values())
    expected_frequency = total_chars / len(frequency)
    entropy = -sum((freq / total_chars) * math.log2(freq / total_chars) for freq in frequency.values())
    print('Entropy:', entropy)
    print('Character Frequency:')
    for char, freq in frequency.items():
        print(f'{char}: {freq}')

    # Print the actual byte values of the first few bytes of the data
    print('Actual byte values of the first few bytes:', data[:20])  

    # Update the custom magic number to match the expected format
    custom_magic_number = b'3=U\xb3\xac\xb66|c\xf2\x0f\xe3\xa3\xdc'  # Ensure this matches the expected header

    # Ensure data is in bytes format
    if isinstance(data, str):
        data = data.encode('latin-1')  # Convert to bytes using latin-1 encoding

    # Check if the first few bytes match the custom magic number
    print('Checking for custom magic number...')
    print('Actual byte values of the first few bytes:', data[:20])
    if data.startswith(custom_magic_number):
        print('File format identified: Custom File Format')
    else:
        print('File format could not be identified')

    # Known file headers (magic numbers)
    file_signatures = {
        b'\x89PNG': 'PNG Image',
        b'GIF8': 'GIF Image',
        b'\xFF\xD8': 'JPEG Image',
        b'%PDF': 'PDF Document',
        b'PK': 'ZIP Archive',
        b'RIFF': 'WAV/AVI File',
        b'\x7FELF': 'ELF Executable',
        b'\x42\x5A': 'BZ2 Compressed',
        b'TXT': 'Text File',
        b'\xFF\xFB': 'MP3 Audio',
        b'\x00\x00\x00\x20ftyp': 'MP4 Video',
        b'<!DOCTYPE html>': 'HTML Document',
        b'<?xml': 'XML Document',
        b'PK\x03\x04': 'ZIP Archive (File Header)',
        b'\x52\x61\x72\x21': 'RAR Archive',
        b'\x1F\x8B': 'GZIP Compressed',
        b'\x4D\x5A': 'EXE Executable',
        b'\x30\x26\xB2\x75': 'WMV Video',
        b'\x66\x74\x79\x70': 'FLV Video',
        b'\x7B\x5C': 'JSON Document',
        b'\x25\x50\x44\x46': 'PDF Document',
        b'\x4D\x53\x57\x4F': 'MS Word Document',
        b'\x4D\x53\x45\x58': 'MS Excel Document',
        b'\x4D\x53\x50\x50': 'MS PowerPoint Document',
        b'\x4D\x53\x41\x43': 'MS Access Database',
        b'\x4D\x53\x50\x53': 'MS Project File',
        b'\x4D\x53\x56\x42': 'MS Visio File',
        b'\x4D\x53\x49\x4D': 'MS Image File',
        b'\x4D\x53\x49\x43': 'MS Icon File',
        b'\x4D\x53\x49\x42': 'MS Bitmap File',
        b'\x4D\x53\x49\x50': 'MS Picture File',
        b'\x4D\x53\x49\x47': 'MS GIF File',
        b'\x4D\x53\x49\x4A': 'MS JPEG File',
        b'\x4D\x53\x49\x50\x4E\x47': 'MS PNG File',
        b'\x4D\x53\x49\x42\x4D\x50': 'MS BMP File',
        b'\x4D\x53\x49\x43\x4F\x4E': 'MS ICO File',
        b'\x4D\x53\x49\x43\x55\x52': 'MS CUR File',
        b'\x4D\x53\x49\x41\x4E\x49': 'MS ANI File',
    }

    # Update the file_signatures dictionary with additional known signatures
    file_signatures.update({
        b'3=U': 'Custom Format',  
        b'3=U\xb3': 'Possible Format',  
        # Add more signatures as necessary
    })

    # Check for known file signatures
    for signature, file_type in file_signatures.items():
        if data.startswith(signature):
            print(f'Identified file format: {file_type}')
            break
    else:
        print('File format could not be identified')

    # Define the packet structure according to the protocol
    packet_structure = {
        'header': {'type': 'byte', 'length': 1},
        'length': {'type': 'int', 'length': 4},
        'payload': {'type': 'bytes', 'length': None},  # Length will be defined by the 'length' field
        'checksum': {'type': 'byte', 'length': 1}
    }

    # Function to parse the packet based on the defined structure
    def parse_packet(data):
        print('Raw Data:', data)  # Print the raw data for debugging
        offset = 0
        parsed_data = {}

        # Print raw data for debugging in a readable format
        print('Raw data (hex):', data.hex())

        # Parse header
        parsed_data['header'] = data[offset:offset + packet_structure['header']['length']]
        offset += packet_structure['header']['length']

        # Parse length
        length_bytes = data[offset:offset + packet_structure['length']['length']]
        print(f'Raw Length Bytes: {length_bytes} (hex: {length_bytes.hex()})')  # Print the raw length bytes before conversion
        parsed_data['length'] = int.from_bytes(length_bytes, 'little')  # Change to little-endian
        offset += packet_structure['length']['length']

        # Debugging information for length
        print('Parsed Length:', parsed_data['length'])
        print('Length Bytes (decimal):', int.from_bytes(length_bytes, 'big'))  # Print as decimal

        # Check length in little-endian format
        parsed_length_le = int.from_bytes(length_bytes, 'little')
        print('Length Bytes (little-endian decimal):', parsed_length_le)

        # Print the length bytes in context
        print('Length Bytes in Context (hex):', data[offset - packet_structure['length']['length'] - packet_structure['header']['length']:offset + 10].hex())

        # Print additional surrounding bytes for more context
        print('Additional Surrounding Raw Data:', data[offset - 15:offset + 15].hex())

        # Print the entire raw data for further inspection
        print('Entire Raw Data:', data.hex())

        # Check if the parsed length is valid
        if parsed_data['length'] > len(data):
            print('Error: Parsed length exceeds total data length. Check data structure.')
            return parsed_data

        # Debugging information before parsing payload
        print('Debug Info:')
        print(f'Parsed Length: {parsed_data["length"]}')
        print(f'Offset: {offset}')
        print(f'Total Data Length: {len(data)}')
        print(f'Payload Start Offset: {offset}')
        print(f'Payload End Offset: {offset + parsed_data["length"]}')
        print(f'Payload Length: {parsed_data["length"]}')
        print(f'Payload Slice: {data[offset:offset + parsed_data["length"]]}')

        # Check if the offset plus length exceeds data length
        if offset + parsed_data['length'] > len(data):
            print('Error: Attempting to access payload beyond data length. Adjust length or input data.');
            return parsed_data

        # Check the validity of the parsed length before parsing the payload
        print(f'Offset: {offset}, Total Data Length: {len(data)}')  # Print offset and total data length
        print(f'Offset Before Payload: {offset}')  # Print offset before payload
        print(f'Total Data Length Before Payload: {len(data)}')  # Print total data length before payload
        print(f'Offset Before Payload (hex): {offset:x}')  # Print offset before payload in hex
        print(f'Total Data Length Before Payload (hex): {len(data):x}')  # Print total data length before payload in hex
        if parsed_data['length'] <= 0 or parsed_data['length'] > len(data) - offset:
            print(f"Error: Invalid payload length {parsed_data['length']} at offset {offset}.")
            return parsed_data

        try:
            # Parse payload
            parsed_data['payload'] = data[offset:offset + parsed_data['length']]
            offset += parsed_data['length']

            # Debugging information
            print('Parsed Data:', parsed_data)  # Print the entire parsed_data dictionary
            print('Parsed Data After Payload:', parsed_data)  # Print the entire parsed_data dictionary after parsing payload
            print('Entire Parsed Data Dictionary:', parsed_data)  # Print the entire parsed_data dictionary
        except IndexError as e:
            print(f"Error: {e}. Check data structure and length.")
            return parsed_data

        # Debugging information for offset and lengths
        print('Offset before parsing checksum:', offset)
        print('Total data length:', len(data))
        print('Expected packet length including checksum:', parsed_data['length'] + packet_structure['header']['length'] + packet_structure['length']['length'] + packet_structure['checksum']['length'])

        # Parse checksum (assuming it's the last byte of the packet)
        parsed_data['checksum'] = data[offset:offset + packet_structure['checksum']['length']]

        # Debugging information
        print('Parsed Packet:', parsed_data)

        return parsed_data

    # Function to calculate checksum
    def calculate_checksum(data):
        return sum(data) % 256  # Simple checksum calculation (mod 256)

    # Call the parse_packet function with the data
    parsed_packet = parse_packet(data)
    print('Parsed Packet:', parsed_packet)

    # Calculate and validate the checksum
    calculated_checksum = calculate_checksum(parsed_packet['payload'])
    if calculated_checksum == parsed_packet['checksum'][0]:  # Assuming checksum is a single byte
        print('Checksum is valid.')
    else:
        print('Checksum is invalid.')

    # Frequency Test
    freq_deviation = {char: freq - expected_frequency for char, freq in frequency.items()}
    print('Frequency Test Deviation:')
    for char, deviation in freq_deviation.items():
        print(f'{char}: {deviation}')

    # Runs Test
    runs = 0
    last_char = None
    for char in data:
        if char != last_char:
            runs += 1
        last_char = char
    print(f'Runs Test: {runs} runs found.')

    # Chi-Squared Test
    chi_squared = sum((freq - expected_frequency) ** 2 / expected_frequency for freq in frequency.values())
    print(f'Chi-Squared Test Statistic: {chi_squared}')

    # Extract features
    features = {'entropy': entropy}
    features.update(frequency)
    df = pd.DataFrame(list(features.items()), columns=['Feature', 'Value'])
    print('Extracted Features:')
    print(df)

    # Visualize character frequencies
    plt.figure(figsize=(12, 6))
    sns.set_style('whitegrid')
    sns.barplot(x=list(frequency.keys()), y=list(frequency.values()))
    plt.title('Character Frequency Distribution')
    plt.xlabel('Characters')
    plt.ylabel('Frequency')
    plt.xticks(rotation=90)
    plt.tight_layout()
    plt.show()

    # Visualize entropy
    plt.figure(figsize=(8, 4))
    sns.set_style('whitegrid')
    plt.plot([entropy], marker='o')
    plt.title('Entropy Visualization')
    plt.xlabel('Segment')
    plt.ylabel('Entropy')
    plt.grid()
    plt.show()

# Call the analyze_data function
analyze_data(data)