# MakeWindowsGreatAgain

**MakeWindowsGreatAgain** is a script designed to **optimize** and **streamline** the performance of Windows 10 and Windows 11. By removing unnecessary pre-installed apps, disabling redundant features, and reducing idle RAM usage, this script ensures that your Windows experience is faster, lighter, and more efficient.

### ![Overview](https://img.shields.io/badge/Overview-Overview-blue)

- **Purpose**: To improve the performance of your system by removing unnecessary bloatware and disabling non-essential services.
- **Targeted Operating Systems**: Windows 10 and Windows 11.
- **Main Focus**: Reducing idle RAM usage, eliminating unnecessary services, and optimizing system processes.
  
### ![Languages](https://img.shields.io/badge/Languages-Batch%20%26%20PowerShell-lightgray)
![Windows](https://img.shields.io/badge/OS-Windows-blue)

By using this script, you can significantly reduce background processes and memory usage, resulting in faster system performance and a more responsive operating system. The goal is to create a cleaner, more efficient Windows environment.

## ![Prerequisites](https://img.shields.io/badge/Prerequisites-Required%20Actions-orange)

Before running this script, ensure that you meet the following requirements:

1. **Full Windows Update**:
   - Make sure your Windows operating system is fully up to date. This includes both regular updates and optional updates. Some features or services that may be disabled by this script might require the latest system updates to function properly.
   
2. **Clean Installation of Drivers**:
   - For the best results, use clean, up-to-date drivers. The script is optimized to work with the latest driver configurations.
     - **For NVIDIA users**: You can use the [NVCleanInstall](https://www.techpowerup.com/download/techpowerup-nvcleanstall/) tool to cleanly install NVIDIA drivers and remove unnecessary components.
     - **For AMD users**: Use [RadeonSoftwareSlimmer](https://github.com/GSDragoon/RadeonSoftwareSlimmer) to slim down your AMD drivers and remove unneeded features.
     - When installing drivers, feel free to disable or remove components that you do not need for your particular setup.

## ![How to Use](https://img.shields.io/badge/How%20to%20Use-Step%20by%20Step-green)

To get started, follow these simple steps:

1. Download the latest version of the script from the [Releases](https://github.com/gyp1jsi/MakeWindowsGreatAgain/releases) page.
2. Once downloaded, extract the contents of the ZIP file.
3. Navigate to the extracted folder and run the **"RUN ME AS ADMIN.bat"** file as an **administrator**. This ensures the script has the necessary privileges to make system-wide changes.

By executing the script with administrative rights, the tool will be able to make system modifications such as disabling services, uninstalling bloatware, and optimizing the registry.

---

## ![Extreme Mode](https://img.shields.io/badge/Extreme%20Mode-Advanced%20User-red)

The **Extreme Mode** is designed for advanced users who want to disable core Windows functionalities for maximum performance improvements. This mode may lead to the loss of certain system features, and as such, it is recommended only for experienced users who are comfortable with troubleshooting.

### **Important Notes for Extreme Mode**:
- **No Active Support**: Once **Extreme Mode** is activated, active support will not be provided for any issues that arise. Please proceed with caution.
- **Be Aware of the Impact**: This mode disables key Windows features and may cause some functions to break or become unavailable.
  
  Some critical services may need to be manually restored if you encounter issues:
  
  - **Troubleshooting Services**:
    - "_Diagnostic Policy Service_" (DPS)
    - "_Diagnostic Execution Service_" (diagsvc)
  
  - **Printing Services**:
    - "_Print Spooler_" (Spooler)
    - "_PrintNotify_" (Printer Extensions and Notifications)
    - "_Server_" (LanmanServer)
    - "_Workstation_" (LanmanWorkstation)
    
    These four services should be set to "Automatic" to ensure that printing functions work properly. If they are set to "Manual," they will not automatically start when needed.

  - **Trackpad Services**:
    - "_ELAN Service_" (ETDService)
  
  - **NVIDIA Control Panel**:
    - "_NVIDIA Display Container LS_" (NVDisplay.ContainerLocalSystem)
  
  In Extreme Mode, these services will be disabled unless manually configured.

---

## ![Contribute](https://img.shields.io/badge/Contribute-Contribution%20Guide-yellow)

We encourage the community to contribute to the development and improvement of **MakeWindowsGreatAgain**. If you have ideas for enhancements or bug fixes, please feel free to contribute by creating a pull request.

### **How to Contribute**:
1. Fork the repository on GitHub.
2. Create a new branch and implement your changes.
3. Test your changes thoroughly to ensure they don’t break existing functionality.
4. Submit a pull request to the **untested** branch for review.
   
Once your changes are tested and verified, they will be merged into the main branch and made available to all users.

---

## ![Disclaimer](https://img.shields.io/badge/Disclaimer-User%20Risks%20Involved-lightgray)

**MakeWindowsGreatAgain** is a tool intended for users who want to optimize their system performance by removing unwanted features and services. While the script is designed to enhance your system's performance, it is important to note that **any modifications you make are at your own risk**. 

By using this script, you acknowledge that you have backed up your data and understand the potential risks involved in modifying system services. The script is provided "as is," and the creators do not offer active support for issues arising from its use.

If you're unsure about any changes or need more information, feel free to review the documentation on the GitHub page or consult with other users who may have experience with the tool.

---

## ![Final Notes](https://img.shields.io/badge/Final%20Notes-System%20Performance%20Optimized-purple)

If you're looking to speed up your Windows system, optimize memory usage, and remove unnecessary bloat, **MakeWindowsGreatAgain** can help you achieve that. Whether you’re using Windows 10 or 11, this script will help you streamline your system, allowing for better performance and a cleaner environment.

Don't forget to regularly check for updates on the [Releases](https://github.com/gyp1jsi/MakeWindowsGreatAgain/releases) page to ensure you're using the latest version of the script.
