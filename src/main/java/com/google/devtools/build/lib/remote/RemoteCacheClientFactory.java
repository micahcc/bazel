// Copyright 2016 The Bazel Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.devtools.build.lib.remote;

import com.google.devtools.build.lib.authandtls.AuthAndTLSOptions;
import com.google.auth.Credentials;
import com.google.common.base.Ascii;
import com.google.common.base.Preconditions;
import com.google.common.collect.ImmutableList;
import com.google.devtools.build.lib.remote.common.RemoteCacheClient;
import com.google.devtools.build.lib.remote.disk.DiskAndRemoteCacheClient;
import com.google.devtools.build.lib.remote.disk.DiskCacheClient;
import com.google.devtools.build.lib.remote.http.HttpCacheClient;
import com.google.devtools.build.lib.remote.options.RemoteOptions;
import com.google.devtools.build.lib.remote.util.DigestUtil;
import com.google.devtools.build.lib.vfs.Path;
import com.google.devtools.build.lib.vfs.PathFragment;
import io.netty.channel.unix.DomainSocketAddress;
import java.io.IOException;
import java.net.URI;
import javax.annotation.Nullable;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class IniFile {

    private Pattern  _section  = Pattern.compile( "\\s*\\[([^]]*)\\]\\s*" );
    private Pattern  _keyValue = Pattern.compile( "\\s*([^=]*)=(.*)" );
    private Map< String,
            Map< String,
            String >>  _entries  = new HashMap<>();

    public IniFile( String path ) throws IOException {
        try( BufferedReader br = new BufferedReader( new FileReader( path ))) {
            String line;
            String section = null;
            while(( line = br.readLine()) != null ) {
                Matcher m = _section.matcher( line );
                if( m.matches()) {
                    section = m.group( 1 ).trim();
                }
                else if( section != null ) {
                    m = _keyValue.matcher( line );
                    if( m.matches()) {
                        String key   = m.group( 1 ).trim();
                        String value = m.group( 2 ).trim();
                        Map< String, String > kv = _entries.get( section );
                        if( kv == null ) {
                            _entries.put( section, kv = new HashMap<>());
                        }
                        kv.put( key, value );
                    }
                }
            }
        }
    }

    public String getString(String section, String key) throws IOException {
        Map< String, String > kv = _entries.get( section );
        if( kv == null ) {
            throw new IOException("Failed to read INI key: " + key);
        }
        return kv.get( key );
    }
}
/**
 * A factory class for providing a {@link RemoteCacheClient}. Currently implemented for HTTP and
 * disk caching.
 */
public final class RemoteCacheClientFactory {

  private RemoteCacheClientFactory() {}

  public static RemoteCacheClient createDiskAndRemoteClient(
      Path workingDirectory,
      PathFragment diskCachePath,
      boolean remoteVerifyDownloads,
      DigestUtil digestUtil,
      RemoteCacheClient remoteCacheClient,
      RemoteOptions options)
      throws IOException {
    DiskCacheClient diskCacheClient =
        createDiskCache(workingDirectory, diskCachePath, remoteVerifyDownloads, digestUtil);
    return new DiskAndRemoteCacheClient(diskCacheClient, remoteCacheClient, options);
  }

  public static RemoteCacheClient create(
      RemoteOptions options,
      @Nullable Credentials creds,
      Path workingDirectory,
      DigestUtil digestUtil,
      AuthAndTLSOptions authAndTLSOptions)
      throws IOException {
    Preconditions.checkNotNull(workingDirectory, "workingDirectory");
    if (isHttpCache(options) && isDiskCache(options)) {
      return createDiskAndHttpCache(
          workingDirectory, options.diskCache, options, creds, digestUtil, authAndTLSOptions);
    }
    if (isHttpCache(options)) {
      return createHttp(options, creds, digestUtil, authAndTLSOptions);
    }
    if (isDiskCache(options)) {
      return createDiskCache(
          workingDirectory, options.diskCache, options.remoteVerifyDownloads, digestUtil);
    }
    throw new IllegalArgumentException(
        "Unrecognized RemoteOptions configuration: remote Http cache URL and/or local disk cache"
            + " options expected.");
  }

  public static boolean isRemoteCacheOptions(RemoteOptions options) {
    return isHttpCache(options) || isDiskCache(options);
  }

  private static RemoteCacheClient createHttp(
      RemoteOptions options, Credentials creds, DigestUtil digestUtil,
      AuthAndTLSOptions authAndTLSOptions) {
    Preconditions.checkNotNull(options.remoteCache, "remoteCache");

    try {
      URI uri = URI.create(options.remoteCache);
      Preconditions.checkArgument(
          Ascii.toLowerCase(uri.getScheme()).startsWith("http"),
          "remoteCache should start with http");

      if (options.remoteProxy != null) {
        if (options.remoteProxy.startsWith("unix:")) {
          return HttpCacheClient.create(
              new DomainSocketAddress(options.remoteProxy.replaceFirst("^unix:", "")),
              uri,
              Math.toIntExact(options.remoteTimeout.getSeconds()),
              options.remoteMaxConnections,
              options.remoteVerifyDownloads,
              ImmutableList.copyOf(options.remoteHeaders),
              digestUtil,
              creds,
              null, null);
        } else {
          throw new Exception("Remote cache proxy unsupported: " + options.remoteProxy);
        }
      } else {
        String awsId = null;
        String awsSecret = null;
        if(authAndTLSOptions.awsProfile != null) {
            String home = System.getenv("HOME");
            try {
                IniFile iniFile = new IniFile(home +"/.aws/credentials");
                awsId = iniFile.getString(authAndTLSOptions.awsProfile, "aws_access_key_id");
                awsSecret = iniFile.getString(authAndTLSOptions.awsProfile, "aws_secret_access_key");
            } catch(Exception e) {
                throw new Exception("Failed to read aws profile: " + authAndTLSOptions.awsProfile + " from ~/.aws/credentials");
            }
        }
        return HttpCacheClient.create(
            uri,
            Math.toIntExact(options.remoteTimeout.getSeconds()),
            options.remoteMaxConnections,
            options.remoteVerifyDownloads,
            ImmutableList.copyOf(options.remoteHeaders),
            digestUtil,
            creds,
            awsId, awsSecret);
      }
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  private static DiskCacheClient createDiskCache(
      Path workingDirectory,
      PathFragment diskCachePath,
      boolean verifyDownloads,
      DigestUtil digestUtil)
      throws IOException {
    Path cacheDir =
        workingDirectory.getRelative(Preconditions.checkNotNull(diskCachePath, "diskCachePath"));
    if (!cacheDir.exists()) {
      cacheDir.createDirectoryAndParents();
    }
    return new DiskCacheClient(cacheDir, verifyDownloads, digestUtil);
  }

  private static RemoteCacheClient createDiskAndHttpCache(
      Path workingDirectory,
      PathFragment diskCachePath,
      RemoteOptions options,
      Credentials cred,
      DigestUtil digestUtil,
      AuthAndTLSOptions authAndTLSOptions)
      throws IOException {
    Path cacheDir =
        workingDirectory.getRelative(Preconditions.checkNotNull(diskCachePath, "diskCachePath"));
    if (!cacheDir.exists()) {
      cacheDir.createDirectoryAndParents();
    }

    RemoteCacheClient httpCache = createHttp(options, cred, digestUtil, authAndTLSOptions);
    return createDiskAndRemoteClient(
        workingDirectory,
        diskCachePath,
        options.remoteVerifyDownloads,
        digestUtil,
        httpCache,
        options);
  }

  public static boolean isDiskCache(RemoteOptions options) {
    return options.diskCache != null && !options.diskCache.isEmpty();
  }

  public static boolean isHttpCache(RemoteOptions options) {
    return options.remoteCache != null
        && (Ascii.toLowerCase(options.remoteCache).startsWith("http://")
            || Ascii.toLowerCase(options.remoteCache).startsWith("https://"));
  }
}
