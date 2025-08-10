#!/bin/bash
# ==============================================================================
# The Ultimate Security Toolset Installer
#
# Author: Your Name (Built with assistance from Gemini)
# GitHub: https://github.com/your-username/your-repo
#
# This script automates the setup of complete toolkits for Pentesters,
# CTF Players, and Digital Forensics Investigators on Debian-based systems.
# ==============================================================================

# --- Configuration & Colors ---
# Directory where tools from GitHub will be cloned
TOOLS_DIR="$HOME/tools"

# Color codes for better user experience
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Tool Definitions ---
# Using associative arrays to hold tool lists for each category.
# Format: "ToolName|InstallType|Source"
# InstallType can be: apt, git, pip, custom

declare -A PENTEST_TOOLS
PENTEST_TOOLS=(
    ["Nmap"]="nmap|apt|nmap"
    ["Masscan"]="masscan|apt|masscan"
    ["theHarvester"]="theHarvester|apt|theharvester"
    ["Amass"]="Amass|git|https://github.com/owasp-amass/amass.git"
    ["Sublist3r"]="Sublist3r|git|https://github.com/aboul3la/Sublist3r.git"
    ["Nikto"]="Nikto|apt|nikto"
    ["Gobuster"]="Gobuster|apt|gobuster"
    ["ffuf"]="ffuf|apt|ffuf"
    ["WPScan"]="WPScan|apt|wpscan"
    ["Nuclei"]="Nuclei|custom|nuclei" # Custom install function
    ["sqlmap"]="sqlmap|apt|sqlmap"
    ["Metasploit"]="Metasploit Framework|apt|metasploit-framework"
    ["SearchSploit"]="SearchSploit|apt|exploitdb"
    ["Evil-WinRM"]="Evil-WinRM|pip|evil-winrm"
    ["Impacket"]="Impacket|pip|impacket"
    ["BloodHound"]="BloodHound|git|https://github.com/BloodHoundAD/BloodHound.git"
    ["John the Ripper"]="John the Ripper|apt|john"
    ["Hashcat"]="Hashcat|apt|hashcat"
    ["Hydra"]="Hydra|apt|hydra"
    ["Aircrack-ng"]="Aircrack-ng|apt|aircrack-ng"
)

declare -A CTF_TOOLS
CTF_TOOLS=(
    ["pwntools"]="pwntools|pip|pwntools"
    ["GDB PEDA"]="GDB-PEDA|git|https://github.com/longld/peda.git"
    ["Ghidra"]="Ghidra|custom|ghidra" # Custom install function
    ["radare2"]="radare2|apt|radare2"
    ["CyberChef"]="CyberChef|git|https://github.com/gchq/CyberChef.git"
    ["Zsteg"]="Zsteg|apt|zsteg"
    ["StegSolve"]="StegSolve|custom|stegsolve" # Custom install function
    ["requests"]="requests|pip|requests"
    ["RSACtfTool"]="RSACtfTool|git|https://github.com/RsaCtfTool/RsaCtfTool.git"
    ["Binwalk"]="Binwalk|apt|binwalk"
    ["ExifTool"]="ExifTool|apt|exiftool"
    ["Volatility 3"]="Volatility 3|git|https://github.com/volatilityfoundation/volatility3.git"
)

declare -A FORENSICS_TOOLS
FORENSICS_TOOLS=(
    ["Guymager"]="Guymager|apt|guymager"
    ["The Sleuth Kit"]="The Sleuth Kit|apt|sleuthkit"
    ["Autopsy"]="Autopsy|apt|autopsy"
    ["Volatility 3"]="Volatility 3|git|https://github.com/volatilityfoundation/volatility3.git"
    ["Binwalk"]="Binwalk|apt|binwalk"
    ["ExifTool"]="ExifTool|apt|exiftool"
    ["Bulk Extractor"]="Bulk Extractor|apt|bulk-extractor"
    ["Wireshark"]="Wireshark|apt|wireshark"
)

# --- Helper & Installation Functions ---

# Function to print a status message
status() {
    echo -e "${BLUE}[*] $1${NC}"
}

# Function to print a success message
success() {
    echo -e "${GREEN}[+] $1${NC}"
}

# Function to print a warning message
warning() {
    echo -e "${YELLOW}[!] $1${NC}"
}

# Function to handle apt installations
install_apt() {
    status "Installing $1..."
    if ! command -v "$2" &> /dev/null; then
        sudo apt-get install -y "$2" >/dev/null 2>&1
        success "$1 installed."
    else
        warning "$1 is already installed."
    fi
}

# Function to handle git clones
install_git() {
    status "Cloning $1..."
    local tool_dir_name=$(basename "$2" .git)
    if [ ! -d "$TOOLS_DIR/$tool_dir_name" ]; then
        git clone "$2" "$TOOLS_DIR/$tool_dir_name" >/dev/null 2>&1
        success "$1 cloned to $TOOLS_DIR/$tool_dir_name."
    else
        warning "$1 directory already exists."
    fi
}

# Function to handle pip installations
install_pip() {
    status "Installing Python package $1..."
    if ! pip3 list | grep -F "$1" > /dev/null; then
        pip3 install "$1" >/dev/null 2>&1
        success "$1 installed via pip."
    else
        warning "$1 is already installed."
    fi
}

# --- Custom Installation Functions ---

install_nuclei() {
    status "Installing Nuclei..."
    if ! command -v "nuclei" &> /dev/null; then
        # Using pre-compiled binary for simplicity
        go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
        success "Nuclei installed."
    else
        warning "Nuclei is already installed."
    fi
}

install_ghidra() {
    warning "Ghidra requires manual installation due to its size and Java dependency."
    warning "Please download it from: https://ghidra-sre.org/"
    status "A placeholder directory will be created at $TOOLS_DIR/ghidra."
    mkdir -p "$TOOLS_DIR/ghidra"
}

install_stegsolve() {
    status "Installing StegSolve..."
    if [ ! -f "$TOOLS_DIR/stegsolve/stegsolve.jar" ]; then
        mkdir -p "$TOOLS_DIR/stegsolve"
        wget "http://www.caesum.com/handbook/Stegsolve.jar" -O "$TOOLS_DIR/stegsolve/stegsolve.jar" >/dev/null 2>&1
        # Create a launcher script
        echo '#!/bin/bash\njava -jar '"$TOOLS_DIR/stegsolve/stegsolve.jar"'' > "$TOOLS_DIR/stegsolve/stegsolve"
        chmod +x "$TOOLS_DIR/stegsolve/stegsolve"
        sudo ln -s "$TOOLS_DIR/stegsolve/stegsolve" /usr/local/bin/stegsolve
        success "StegSolve installed. You can run it with the 'stegsolve' command."
    else
        warning "StegSolve appears to be already installed."
    fi
}

# --- Main Logic ---

# Generic function to display and install a toolset
process_selection() {
    local -n tools=$1 # Use nameref to pass the associative array
    local title=$2

    echo -e "\n${YELLOW}--- Tools for $title Setup ---${NC}"
    for key in "${!tools[@]}"; do
        IFS='|' read -r name type source <<< "${tools[$key]}"
        echo -e "- ${GREEN}$name${NC} (via $type)"
    done

    echo ""
    read -p "Do you want to install this toolset? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        echo -e "${RED}Installation cancelled.${NC}"
        return
    fi

    status "Starting $title setup..."
    for key in "${!tools[@]}"; do
        IFS='|' read -r name type source <<< "${tools[$key]}"
        case "$type" in
            apt) install_apt "$name" "$source" ;;
            git) install_git "$name" "$source" ;;
            pip) install_pip "$source" ;;
            custom)
                case "$source" in
                    nuclei) install_nuclei ;;
                    ghidra) install_ghidra ;;
                    stegsolve) install_stegsolve ;;
                esac
                ;;
        esac
    done
    success "$title setup complete!"
}

# Main menu for the user
main_menu() {
    echo -e "${BLUE}=====================================================${NC}"
    echo -e "${YELLOW}      Welcome to the Ultimate Toolset Installer      ${NC}"
    echo -e "${BLUE}=====================================================${NC}"
    echo "This script will help you set up your environment."
    echo "Tools from GitHub will be installed in: $TOOLS_DIR"
    mkdir -p "$TOOLS_DIR"

    PS3=$'\n'"Please select the setup you want to install: "
    options=("Pentest Setup" "CTF Setup" "Forensics Setup" "Quit")
    select opt in "${options[@]}"; do
        case $opt in
            "Pentest Setup")
                process_selection PENTEST_TOOLS "Pentest"
                break
                ;;
            "CTF Setup")
                process_selection CTF_TOOLS "CTF"
                break
                ;;
            "Forensics Setup")
                process_selection FORENSICS_TOOLS "Forensics"
                break
                ;;
            "Quit")
                break
                ;;
            *) echo "Invalid option $REPLY";;
        esac
    done
}

# --- Script Execution ---
main_menu
echo -e "\n${GREEN}All selected operations are complete. Happy hacking!${NC}\n"
