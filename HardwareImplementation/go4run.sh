#/bin/bash

#################################################
# Change your program name here
#################################################
P4_NAME="couper"
#################################################
# Change your program name here
# DO NOT touch the following contents
#################################################

P4_PATH=`pwd`/${P4_NAME}".p4"
SKIP_CONFIGURE_FLAG=false
SKIP_CLEAN_FLAG=false
SKIP_INSTALL_FLAG=false
SKIP_RUN_FLAG=false
RUN_P4I_FLAG=false

USAGE=$(cat <<-END
Usage: 
  ./go4run.sh [OPTIONS]...
Description:
  This script sets up your P4 project structure, compiles it, installs it and runs it.
  Place your P4 code along with this script in a clean directory, enters ./go4run.sh and everything will be prepared.
Options:
  --help, -h        Print this information
  --skip-configure  Skip configuration
  --skip-clean      Skip running 'make clean' before 'make'
  --skip-install    Stop after compilation, skip installation and run
  --skip-run        Stop after installation, skip run
  --p4i             Stop after compilation and launches p4i
Examples:
  ./go4run.sh       Configure + Clean + Compile + Install + Run
  ./go4run.sh --p4i Configure + Clean + Compile + p4i
END
)

CONF_TEMPLATE=$(cat <<-END
{
    "chip_list": [
        {
            "id": "asic-0",
            "chip_family": "Tofino",
            "instance": 0,
            "pcie_sysfs_prefix": "/sys/devices/pci0000:00/0000:00:03.0/0000:05:00.0",
            "pcie_domain": 0,
            "pcie_bus": 5,
            "pcie_fn": 0,
            "pcie_dev": 0,
            "pcie_int_mode": 1,
            "sds_fw_path": "share/tofino_sds_fw/avago/firmware"
        }
    ],
    "id": "<placeholder>.csv",
    "instance": 0,
    "p4_program_list": [
        {
            "id": "pgm-0",
            "instance": 0,
            "path": "<placeholder>",
            "program-name": "<placeholder>",
            "pd": "lib/tofinopd/<placeholder>/libpd.so",
            "pd-thrift": "lib/tofinopd/<placeholder>/libpdthrift.so",
            "table-config": "share/tofinopd/<placeholder>/pipe/context.json",
            "tofino-bin": "share/tofinopd/<placeholder>/pipe/tofino.bin",
            "bfrt-config": "share/tofinopd/<placeholder>/bf-rt.json",
            "agent0": "lib/libpltfm_mgr.so"
        }
    ]
}
END
)

VALID_ARGS=$(getopt -o hc --long help,skip-configure,skip-clean,skip-install,skip-run,p4i -n "$0" -- "$@")
if [[ $? -ne 0 ]]; then
    echo "$USAGE"
    exit 1;
fi
eval set -- "$VALID_ARGS"
while [ : ]; do
  case "$1" in
    -h | --help)
        echo "$USAGE"
        exit 0
        ;;
    --skip-configure)
        SKIP_CONFIGURE_FLAG=true
        shift
        ;;
    --skip-clean)
        SKIP_CLEAN_FLAG=true
        shift
        ;;
    --skip-install)
        SKIP_INSTALL_FLAG=true
        SKIP_RUN_FLAG=true
        shift
        ;;
    --skip-run)
        SKIP_RUN_FLAG=true
        shift
        ;;
    --p4i)
        SKIP_INSTALL_FLAG=true
        SKIP_RUN_FLAG=true
        RUN_P4I_FLAG=true
        shift
        ;;
    --) shift; 
        break 
        ;;
  esac
done

echo "[INFO] P4 Program Name:" $P4_NAME
echo "[INFO] P4 Program Path:" $P4_PATH
echo "[INFO] SKIP_CONFIGURE_FLAG: "$SKIP_CONFIGURE_FLAG
echo "[INFO] CLEAN_FLAG: "$CLEAN_FLAG
echo "[INFO] SKIP_INSTALL_FLAG: "$SKIP_INSTALL_FLAG
echo "[INFO] SKIP_RUN_FLAG: "$SKIP_RUN_FLAG

if [ -z "$SDE" ]; then
    echo "[ERROR] SDE is not set"
    exit 1
else
    echo "[INFO] SDE:" $SDE
fi

if [ -z "$SDE_INSTALL" ]; then
    echo "[ERROR] SDE_INSTALL is not set"
    exit 1
else
    echo "[INFO] SDE_INSTALL:" $SDE_INSTALL
fi

if [ -e build ]; then # If build exists
    if [ -d build ]; then # If build is a directory
        echo "[INFO] Found build directory"
    else # If build is a file
        echo "[ERROR] 'build' exists but it is a file"
        exit 1
    fi
else # If build does not exist
    echo "[INFO] Creating build directory"
    mkdir build
fi

cd build

if [ $SKIP_CONFIGURE_FLAG = false ]; then
    echo "[INFO] Configuring..."
    $SDE/pkgsrc/p4-build/configure     \
               --prefix=$SDE_INSTALL   \
               --with-tofino           \
               --with-pd               \
               --with-p4c=p4c          \
               --with-p4-runtime       \
               enable_thrift=yes       \
               P4_VERSION=p4-16        \
               P4_PATH=$P4_PATH        \
               P4_NAME=$P4_NAME        \
               P4_ARCHITECTURE=tna     \
               P4_FLAGS="--verbose 2 --create-graphs -g"
               LDFLAGS="-L$SDE_INSTALL/lib"
fi

if [ $? -ne 0 ]; then
    exit 1
fi

if [ $SKIP_CLEAN_FLAG = false ]; then
    echo "[INFO] Cleaning..."
    make clean
fi
echo "[INFO] Compiling..."
make -j4

if [ $? -ne 0 ]; then
    exit 1
fi

if [ $SKIP_INSTALL_FLAG = false ]; then
    make install
    echo "$CONF_TEMPLATE" | sed "s;<placeholder>;${P4_NAME};" > ${P4_NAME}.conf
    cp -vf ${P4_NAME}.conf $SDE/install/share/p4/targets/tofino/
fi

if [ $SKIP_RUN_FLAG = false ]; then
    $SDE/run_switchd.sh -p ${P4_NAME}
fi

if [ $RUN_P4I_FLAG = true ]; then
    p4i
fi
