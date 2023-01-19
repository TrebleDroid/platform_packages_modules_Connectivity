/*
 * Copyright (C) 2010 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_TAG "NetworkStatsNative"

#include <cutils/qtaguid.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <jni.h>
#include <nativehelper/jni_macros.h>
#include <nativehelper/ScopedUtfChars.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <utils/Log.h>
#include <utils/misc.h>

#include "bpf/BpfUtils.h"
#include "netdbpf/BpfNetworkStats.h"
#include "netdbpf/NetworkTraceHandler.h"

using android::bpf::bpfGetUidStats;
using android::bpf::bpfGetIfaceStats;
using android::bpf::bpfRegisterIface;
using android::bpf::NetworkTraceHandler;

namespace android {

static const char* QTAGUID_IFACE_STATS = "/proc/net/xt_qtaguid/iface_stat_fmt";
static const char* QTAGUID_UID_STATS = "/proc/net/xt_qtaguid/stats";

static struct {
    jclass theClass;
    jmethodID constructor;
    jfieldID rxBytes;
    jfieldID txBytes;
    jfieldID rxPackets;
    jfieldID txPackets;
} gNetworkStatsEntry;

static void nativeRegisterIface(JNIEnv* env, jclass clazz, jstring iface) {
    ScopedUtfChars iface8(env, iface);
    if (!iface8.c_str()) return;
    bpfRegisterIface(iface8.c_str());
}

static jobject statsValueToEntry(JNIEnv* env, StatsValue* stats) {
    // Create a new instance of the Java class
    jobject result = env->NewObject(gNetworkStatsEntry.theClass, gNetworkStatsEntry.constructor);
    if (!result) return nullptr;

    // Set the values of the structure fields in the Java object
    env->SetLongField(result, gNetworkStatsEntry.rxBytes, stats->rxBytes);
    env->SetLongField(result, gNetworkStatsEntry.txBytes, stats->txBytes);
    env->SetLongField(result, gNetworkStatsEntry.rxPackets, stats->rxPackets);
    env->SetLongField(result, gNetworkStatsEntry.txPackets, stats->txPackets);

    return result;
}

static int parseIfaceStats(const char* iface, StatsValue* stats) {
    FILE *fp = fopen(QTAGUID_IFACE_STATS, "r");
    if (fp == NULL) {
        return -1;
    }

    char buffer[384];
    char cur_iface[32];
    uint64_t rxBytes, rxPackets, txBytes, txPackets, tcpRxPackets, tcpTxPackets;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        int matched = sscanf(buffer, "%31s %" SCNu64 " %" SCNu64 " %" SCNu64
                " %" SCNu64 " " "%*u %" SCNu64 " %*u %*u %*u %*u "
                "%*u %" SCNu64 " %*u %*u %*u %*u", cur_iface, &rxBytes,
                &rxPackets, &txBytes, &txPackets, &tcpRxPackets, &tcpTxPackets);
        if (matched >= 5) {
            if (!iface || !strcmp(iface, cur_iface)) {
                stats->rxBytes += rxBytes;
                stats->rxPackets += rxPackets;
                stats->txBytes += txBytes;
                stats->txPackets += txPackets;
            }
        }
    }

    if (fclose(fp) != 0) {
        return -1;
    }
    return 0;
}

static int parseUidStats(const uint32_t uid, StatsValue* stats) {
    FILE *fp = fopen(QTAGUID_UID_STATS, "r");
    if (fp == NULL) {
        return -1;
    }

    char buffer[384];
    char iface[32];
    uint32_t idx, cur_uid, set;
    uint64_t tag, rxBytes, rxPackets, txBytes, txPackets;

    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        if (sscanf(buffer,
                "%" SCNu32 " %31s 0x%" SCNx64 " %u %u %" SCNu64 " %" SCNu64
                " %" SCNu64 " %" SCNu64 "",
                &idx, iface, &tag, &cur_uid, &set, &rxBytes, &rxPackets,
                &txBytes, &txPackets) == 9) {
            if (uid == cur_uid && tag == 0L) {
                stats->rxBytes += rxBytes;
                stats->rxPackets += rxPackets;
                stats->txBytes += txBytes;
                stats->txPackets += txPackets;
            }
        }
    }

    if (fclose(fp) != 0) {
        return -1;
    }
    return 0;
}

static jobject nativeGetTotalStat(JNIEnv* env, jclass clazz) {
    StatsValue stats = {};
    if (bpfGetIfaceStats(nullptr, &stats) == 0) {
        return statsValueToEntry(env, &stats);
    } else {
        if (parseIfaceStats(nullptr, &stats) == 0) {
            return statsValueToEntry(env, &stats);
        } else {
            return nullptr;
        }
    }
}

static jobject nativeGetIfaceStat(JNIEnv* env, jclass clazz, jstring iface) {
    ScopedUtfChars iface8(env, iface);
    if (!iface8.c_str()) return nullptr;

    StatsValue stats = {};
    if (bpfGetIfaceStats(iface8.c_str(), &stats) == 0) {
        return statsValueToEntry(env, &stats);
    } else {
        if (parseIfaceStats(iface8.c_str(), &stats) == 0) {
            return statsValueToEntry(env, &stats);
        } else {
            return nullptr;
        }
    }
}

static jobject nativeGetUidStat(JNIEnv* env, jclass clazz, jint uid) {
    StatsValue stats = {};
    if (bpfGetUidStats(uid, &stats) == 0) {
        return statsValueToEntry(env, &stats);
    } else {
        if (parseUidStats(uid, &stats) == 0) {
            return statsValueToEntry(env, &stats);
        } else {
            return nullptr;
        }
    }
}

static void nativeInitNetworkTracing(JNIEnv* env, jclass clazz) {
    NetworkTraceHandler::InitPerfettoTracing();
}

static const JNINativeMethod gMethods[] = {
    MAKE_JNI_NATIVE_METHOD_AUTOSIG("nativeRegisterIface", nativeRegisterIface),
    MAKE_JNI_NATIVE_METHOD("nativeGetTotalStat", "()Landroid/net/NetworkStats$Entry;", nativeGetTotalStat),
    MAKE_JNI_NATIVE_METHOD("nativeGetIfaceStat", "(Ljava/lang/String;)Landroid/net/NetworkStats$Entry;", nativeGetIfaceStat),
    MAKE_JNI_NATIVE_METHOD("nativeGetUidStat", "(I)Landroid/net/NetworkStats$Entry;", nativeGetUidStat),
    MAKE_JNI_NATIVE_METHOD_AUTOSIG("nativeInitNetworkTracing", nativeInitNetworkTracing),
};

int register_android_server_net_NetworkStatsService(JNIEnv* env) {
    if (jniRegisterNativeMethods(env,
        "android/net/connectivity/com/android/server/net/NetworkStatsService",
        gMethods,
        NELEM(gMethods))) abort();

    // Find the Java class that represents the structure
    jclass clazz = env->FindClass("android/net/NetworkStats$Entry");
    if (!clazz) abort();
    clazz = static_cast<jclass>(env->NewGlobalRef(clazz));
    if (!clazz) abort();
    gNetworkStatsEntry.theClass = clazz;

    // Find the constructor.
    gNetworkStatsEntry.constructor = env->GetMethodID(clazz, "<init>", "()V");
    if (!gNetworkStatsEntry.constructor) abort();

    // and the individual fields...
    gNetworkStatsEntry.rxBytes = env->GetFieldID(clazz, "rxBytes", "J");
    if (!gNetworkStatsEntry.rxBytes) abort();

    gNetworkStatsEntry.txBytes = env->GetFieldID(clazz, "txBytes", "J");
    if (!gNetworkStatsEntry.txBytes) abort();

    gNetworkStatsEntry.rxPackets = env->GetFieldID(clazz, "rxPackets", "J");
    if (!gNetworkStatsEntry.rxPackets) abort();

    gNetworkStatsEntry.txPackets = env->GetFieldID(clazz, "txPackets", "J");
    if (!gNetworkStatsEntry.txPackets) abort();

    return 0;
}

}
