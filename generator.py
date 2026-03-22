"""Generates network traffic.

Looks like multiple computers generating multiple we requests.
Utilizes multiple virtual network interfaces.
Can generate random MAC addresses for each interface.
Can randomly choose from a list of user agent strings.
"""
import argparse
import logging
import os
import random
import signal
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from io import BytesIO

import pycurl
import yaml

send_traffic = threading.Event()

MAX_INTERFACES = 20


def run_command(command_list):
    """Run a given command and return the result code.

    command_list is a list including the command and any arguments.
    """
    try:
        result = subprocess.run(command_list, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            logging.error(f"Return code: {result.returncode}")
            logging.error(f"STDOUT: {result.stdout}")
            logging.error(f"STDERR: {result.stderr}")
    except subprocess.CalledProcessError as e:
        logging.error(f"{command_list[0]} failed with return code {e.returncode}")

    return result


def load_dummy():
    """Load the dummy kenel module that is used to create virtual network interfaces."""
    result = run_command(['modprobe', 'dummy'])
    return result



def generate_random_mac():
    """Generate a valid random MAC address.

    - Locally administered (second least significant bit of first byte is 1)
    - Unicast (least significant bit of first byte is 0)
    """
    # First byte: set locally administered (0x02) and unicast (LSB=0)
    first_byte = random.randint(0x00, 0xFF)
    first_byte = (first_byte & 0b11111100) | 0b00000010  # Ensure LAA and unicast

    # Remaining 5 bytes: fully random
    mac_bytes = [first_byte] + [random.randint(0x00, 0xFF) for _ in range(5)]

    # Format as standard MAC address (e.g., "02:1A:3B:4C:5D:6E")
    return ":".join(f"{byte:02X}" for byte in mac_bytes)


def assign_mac(iface='eth0'):
    """Assign a MAC address to a network interface.

    iface is the network interface to assign the MAC address to.
    returns a tuple of (returncode, stdout, stderr)
    """
    mac = generate_random_mac()

    logging.info(f"Assigning {mac} to {iface}")

    result = run_command(['ip', 'link', 'set', 'dev', iface, 'address', mac])

    return (result.returncode, result.stdout, result.stderr)


def create_interface(iface='eth0'):
    """Create a network interface with name provided by iface.

    returns a tuple of (returncode, stdout, stderr).
    """
    result = run_command(['ip', 'link', 'add', iface, 'type', 'dummy'])

    return (result.returncode, result.stdout, result.stderr)


def assign_ip_address(iface='eth0', ip='10.0.0.1', cidr='24'):
    """Assign a IP address to a network interface.

    Requires the interface, IP addreess and CIDR mask.
    Returns a tuple of (returncode, stdout, stderr).
    """
    iface_colon_0 = iface + ':0'
    ip = str(ip) + '/' + str(cidr)

    result = run_command(['ip', 'addr', 'add', ip, 'brd', '+', 'dev', iface, 'label', iface_colon_0])

    return (result.returncode, result.stdout, result.stderr, iface_colon_0)


def turn_on_interface(iface='eth0'):
    """Turn on/Enable a given network interface.

    Returns a tuple of (returncode, stdout, stderr).
    """
    result = run_command(['ip', 'link', 'set', 'dev', iface, 'up'])

    return (result.returncode, result.stdout, result.stderr)


def delete_interface(iface='eth0'):
    """Delete a given network interface.

    Called when the interface is no longer needed.
    Returns a tuple of (returncode, stdout, stderr).
    """
    result = run_command(['ip', 'link', 'delete', iface, 'type', 'dummy'])

    return (result.returncode, result.stdout, result.stderr)


def setup_interface(iface='eth0', ip_address='10.0.0.1', cidr='24'):
    """setup_interface calls all of the helper functions that create, enable and configure the network interface that will be used.

    returns a tuple of (iface, ip_address, cidr).
    """
    result_tuple = create_interface(iface)
    result_tuple = assign_mac(iface)
    result_tuple = turn_on_interface(iface)
    result_tuple = assign_ip_address(iface, ip_address, cidr)

    #logging.info(result_tuple)
    return result_tuple


def load_user_agent_string_list(input_file):
    """Load a list of user agent strings from a file.

    Takes and input file and returns a list of strings.
    """
    default_string = 'Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'

    #open and read file, with no newlines
    try:
        with open(input_file) as file:
            agent_string_list = file.read().splitlines()
    except OSError:
        logging.error(f"Missing file or unable to read: {user_agent_string_file}  Using default values.")
        agent_string_list=[default_string]


    # filter out lines starting with #
    non_comments = list(filter(lambda x: not x.startswith('#'), agent_string_list))

    return non_comments


def get_agent_string(agent_string_list):
    """Returns a random user agent string."""
    random_choice = random.choice(agent_string_list)
    logging.debug(f"Random_choice: {random_choice}")
    return random_choice





class Sender(threading.Thread):
    """Sender acts as a machine on the network sending traffic.

    Requires a interface_name to send the traffic, URL.
    """

    def __init__(self, url, interface_name, send_traffic, page_list=[], user_agent_list=[]):
        """Initialize the Sender to include optional parameters."""
        super().__init__()
        self.url = url
        self.interface_name = interface_name
        self.send_traffic = send_traffic
        self.page_list = page_list
        self.user_agent_list = user_agent_list



    def __fetch_via_interface(self, url, interface_name, page='', user_agent=''):
        """Fetches the given URL using a specific network interface.

        :param url: The target URL to fetch.
        :param interface_name: The name of the network interface (e.g., 'eth0', 'wlan0').
        :return: Response body as a string.
        """
        buffer = BytesIO()
        curl = pycurl.Curl()

        if user_agent == '': #blank
            user_agent = 'User-Agent: Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148'

        url = str(self.url) + str(page)
        #print(f"Fetch URL: {url}   Interface: {interface_name}")

        try:
            # Set the target URL
            curl.setopt(pycurl.URL, url)

            # Set the network interface to use
            curl.setopt(pycurl.INTERFACE, interface_name)

            # Set the user agent string
            curl.setopt(pycurl.USERAGENT, user_agent)

            # Follow redirects if needed
            curl.setopt(pycurl.FOLLOWLOCATION, True)

            # Set a reasonable timeout
            curl.setopt(pycurl.TIMEOUT, 10)

            # Write response to buffer
            curl.setopt(pycurl.WRITEDATA, buffer)

            # Perform the request
            # This will catch timeouts and move on
            try:
                curl.perform()
            except pycurl.error as e:
                logging.error(f"Connection error for {url}: {e}")
            finally:
                curl.close()
                return False


            # Check HTTP status code
            status_code = curl.getinfo(pycurl.RESPONSE_CODE)
            if status_code != HTTPStatus.OK:
                raise Exception(f"HTTP {url} request failed with status code {status_code}")

            return buffer.getvalue().decode('utf-8')

        except pycurl.error as e:
            raise RuntimeError(f"PycURL error: {e}")
        finally:
            curl.close()

    def __get_pages(self):
        """Gets each web page in a list of provided pages."""
        user_agent = "User-Agent: " + get_agent_string(self.user_agent_list)

        logging.debug(f"self.user_agent = {user_agent}")

        while send_traffic.is_set():
            #randomize page list
            random.shuffle(page_list) # Shuffles in place
            for page in page_list:
                logging.info(f"URL: {self.url}    IFACE: {self.interface_name}  Page: {page}")
                self.__fetch_via_interface(self.url, self.interface_name, page, user_agent)

            time.sleep(2)
        return 0


    def run(self):
        """This method is executed when you call start() on the object."""
        #print(f"Thread for item {self.interface_name}: starting task")

        #print(f"URL: {self.url}    IFACE: {self.interface_name}  Extra: {self.extra}")
        #self.fetch_via_interface(self.url, self.interface_name, self.extra)
        self.__get_pages()

        #print(f"Thread for item {self.iterface_name}: finishing task")


def clean_up(send_traffic):
    """Clears the send_traffic flag and performs any other cleanup."""
    # Clear the flag
    send_traffic.clear()

    return 0


# Custom handler for SIGINT
def sigint_handler(signum, frame):
    """Catches SIGINT CTRL-C and begins cleaing up."""
    logging.info("SIGINT received! Cleaning up...")
    logging.info("Please wait for current sending to finsih...")
    clean_up(send_traffic)

    #sys.exit(0)


def check_root():
    """Verify that use is root, else exit."""
    if os.geteuid() != 0:
        sys.exit("You need to run this script as root. Please use 'sudo' or switch to the root user.")



def load_config(config_file_path):
    """Load the external YAML configuration file."""
    with open(config_file_path) as stream:
        try:
            # Use safe_load for security when loading general config files
            config_data = yaml.safe_load(stream)
            return config_data
        except yaml.YAMLError as exc:
            logging.error(exc)
            return None


def set_log_level(level):
    """Dynamically change the logging level during program run time."""
    logger = logging.getLogger()
    logger.setLevel(level)
    

##### Main ########################
if __name__ == "__main__":
    """Main method that creates the interfaces, instantiates the Senders and cleans up after finished."""

    check_root() #verify user has root privleges!

    #logging.basicConfig(filename='basic.log',encoding='utf-8',level=logging.INFO, filemode = 'w', format='%(process)d-%(levelname)s-%(message)s')
    logging.basicConfig(
        encoding='utf-8',
        level=logging.DEBUG,
        format='%(asctime)s - %(filename)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
        )


    # default config variables
    interface_base = "eth"
    target_base = "http://192.168.4.85"
    starting_ip = '10.0.1.150'
    cidr = '24'
    num_interfaces = 1 #how many virtual interfaces to create and use
    page_list = ['/', '/twiki', '/phpMyAdmin', '/mutillidae', '/dvwa', '/dav']
    user_agent_string_file = 'user_agent_strings.txt'

    # Load the configuration
    config = load_config('generator_config.yaml')

    # Accessing data like a Python dictionary
    if config:
        logging.debug(f"interface_base: {config['interface_base']}")
        interface_base = config['interface_base']
        logging.debug(f"target_base: {config['target_base']}")
        target_base = config['target_base']
        logging.debug(f"starting_ip: {config['starting_ip']}")
        starting_ip = config['starting_ip']
        logging.debug(f"cidr: {config['cidr']}")
        cidr = config['cidr']
        logging.debug(f"num_interfaces: {config['num_interfaces']}")
        num_interfaces = config['num_interfaces']
        logging.debug(f"page_list: {config['page_list']}")
        page_list = config['page_list']
        user_agent_string_file = config['user_agent_string_file']
        logging_level = config['logging_level']
    else:
        logging.warning("Config file could not be read.  Using default values.")


    # Create parser
    parser = argparse.ArgumentParser(description="Generate some network traffic.")

    # Add arguments
    parser.add_argument("-n", "--NumberOfInterfaces", help="How many interfaces to create and use.")
    parser.add_argument("-t", "--TargetBase", help="The base URL of the target (http://192.168.4.85).")
    parser.add_argument("-i", "--StartingIP", help="The IP address to start with for the virtual interfaces.")
    parser.add_argument("-u", "--UserAgentFile", help="File containing user agent strings.")
    parser.add_argument("-p", "--PageList", help="Web pages at the TargetBase to visit.")
    parser.add_argument("-l", "--LoggingLevel", help="Change the logging level.  Default=INFORMATION")

    # Parse the arguments
    args = parser.parse_args()


    if args.NumberOfInterfaces:
        logging.info(f"NumberOfInterfaces = {args.NumberOfInterfaces}")
        num_interfaces = int(args.NumberOfInterfaces)

    if args.TargetBase:
        logging.info(f"TargetBase = {args.TargetBase}")
        target_base = str(args.TargetBase)

    if args.StartingIP:
        logging.info(f"StartingIP = {args.StartingIP}")
        starting_ip = str(args.StartingIP)

    if args.UserAgentFile:
        logging.info(f"UserAgentFile = {args.UserAgentFile}")
        user_agent_string_file = str(args.UserAgentFile)

    if args.PageList:
        logging.info(f"PageList = {args.PageList}")
        page_list = str(args.PageList)

    if args.LoggingLevel:
        logging.info(f"LoggingLevel = {args.LoggingLevel}")
        logging_level = str(args.LoggingLevel)

    logging_level = logging_level.upper()
    #logging.basicConfig(level=logging_level)
    set_log_level(logging_level)

    agent_string_list = load_user_agent_string_list(user_agent_string_file)
    #agent_string = get_agent_string(agent_string_list)
    #print(agent_string)


    # Register the handler
    signal.signal(signal.SIGINT, sigint_handler)

    # Maxiumum number of interfaces is 20
    if int(num_interfaces) > MAX_INTERFACES:
        logging.warning("Maximum number of network interfaces is 20.")
        num_interfaces = MAX_INTERFACES

    send_traffic.set()

    load_dummy()
    interface_label_list = []


    ip_list = starting_ip.split(".")
    #logging.info(ip_list)

    # create and configure the network interfaces
    for i in range(0,num_interfaces):
        interface = interface_base + str(i)

        last_octet = str(int(ip_list[3]) + i)
        #logging.info(last_octet)

        ip_address = ip_list[0] + '.' +  ip_list[1] + '.' + ip_list[2] + '.' + str(last_octet)
        logging.info(f"IPaddress = {ip_address}")

        logging.info(f"Interface = {interface}")
        result_tuple = setup_interface(interface, ip_address, cidr)
        if result_tuple[0] == 0: #good
            interface_label_list.append(result_tuple[3])


    logging.info(interface_label_list)


    object_list = []


    # build list of individual "machine" objects
    for label in interface_label_list:
        try:
            #logging.info(f"Getting via {label}")

            #html = fetch_via_interface(target_base, label, page)
            object_list.append(Sender(target_base, label, send_traffic, page_list, agent_string_list))
            #item_id, url, interface_name, extra='', user_agent=''
            #print("Response:\n", html)
        except Exception as e:
            logging.error(f"Error: {e}")


    # start the "machine" objects
    for item in object_list:
        item.start()

    # Wait for the thread to complete
    for item in object_list:
        item.join()

    # delete interfaces when finished
    for i in range(0,num_interfaces):
        interface = interface_base + str(i)
        delete_interface(interface)


    logging.info("All done sending traffic.")
