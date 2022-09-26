// Copyright 2018 The Bazel Authors. All rights reserved.
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
package com.google.devtools.build.lib.remote.http;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.google.auth.Credentials;
import com.google.common.collect.ImmutableList;
import com.google.common.flogger.GoogleLogger;
import com.google.common.io.BaseEncoding;
import com.google.devtools.build.lib.analysis.BlazeVersionInfo;
import com.google.devtools.build.lib.authandtls.AuthAndTLSOptions;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelOutboundHandler;
import io.netty.channel.ChannelPromise;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.handler.codec.http.HttpHeaderNames;
import io.netty.handler.codec.http.HttpMethod;
import io.netty.handler.codec.http.HttpObject;
import io.netty.handler.codec.http.HttpRequest;
import java.io.IOException;
import java.net.SocketAddress;
import java.net.URI;
import java.nio.channels.ClosedChannelException;
import java.text.SimpleDateFormat;
import java.util.Base64;
import java.util.Calendar;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.TimeZone;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Common functionality shared by concrete classes. */
abstract class AbstractHttpHandler<T extends HttpObject> extends SimpleChannelInboundHandler<T>
    implements ChannelOutboundHandler {

  private static final GoogleLogger logger = GoogleLogger.forEnclosingClass();

  private static final String USER_AGENT_VALUE =
      "bazel/" + BlazeVersionInfo.instance().getVersion();

  private final Credentials credentials;
  private final ImmutableList<Entry<String, String>> extraHttpHeaders;

  private String awsId;
  private String awsSecret;

  public AbstractHttpHandler(
      Credentials credentials,
      ImmutableList<Entry<String, String>> extraHttpHeaders,
      String awsId, String awsSecret) {
    this.credentials = credentials;
    this.extraHttpHeaders = extraHttpHeaders;
    this.awsId = awsId;
    this.awsSecret = awsSecret;
  }

  protected ChannelPromise userPromise;

  @SuppressWarnings("FutureReturnValueIgnored")
  protected void failAndResetUserPromise(Throwable t) {
    if (userPromise != null && !userPromise.isDone()) {
      userPromise.setFailure(t);
    }
    userPromise = null;
  }

  private static String getServerTime() {
    Calendar calendar = Calendar.getInstance();
    SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
    dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
    return dateFormat.format(calendar.getTime());
  }

  private static String hmacSha1(String key, String data) {
    try {
      Mac mac = Mac.getInstance("HmacSHA1");
      SecretKeySpec secret = new SecretKeySpec(key.getBytes(), "HmacSHA1");
      mac.init(secret);
      byte[] digest = mac.doFinal(data.getBytes());
      String out = Base64.getEncoder().encodeToString(digest);
      return out;
    } catch (Exception e) {
      logger.atWarning().withCause(e).log("failed to setup aws creds");
      return "";
    }
  }

  protected void addAwsAuthenticationHeaders(HttpRequest request, String path) throws IOException {
    if (awsId == "" || awsSecret == "") {
      return;
    }

    // x-amz-date
    String dateStr = getServerTime();
    request.headers().add("x-amz-date", dateStr);

    String toHash;
    //   StringToSign = HTTP-Verb + "\n" +
    //   Content-MD5 + "\n" +  (optional)
    //   Content-Type + "\n" + (optional)
    //   Date + "\n" +
    //   CanonicalizedAmzHeaders +
    //   CanonicalizedResource;
    if (request.getMethod() == HttpMethod.GET) {
      // GET\n
      // \n
      // \n
      // Tue, 27 Mar 2007 19:36:42 +0000\n
      // /photos/blob
      toHash = "GET\n\n\n\nx-amz-date:" + dateStr + "\n" + path;
    } else if (request.getMethod() == HttpMethod.PUT) {
      // PUT\n
      // \n
      // application/octet-stream\n
      // Tue, 27 Mar 2007 21:15:45 +0000\n
      // /photos/blob
      toHash = "PUT\n\n\n\nx-amz-date:" + dateStr + "\n" + path;
    } else {
      return;
    }

    String sigStr = hmacSha1(awsSecret, toHash);
    if (sigStr == "") {
      return;
    }
    // Signature = Base64(
    //  HMAC-SHA1(
    //     UTF-8-Encoding-Of(YourSecretAccessKey),
    //     UTF-8-Encoding-Of( StringToSign )
    //  )
    // );
    // Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature;
    request.headers().add("Authorization", "AWS " + awsId + ":" + sigStr);
  }

  protected void addCredentialHeaders(HttpRequest request, URI uri) throws IOException {
    String userInfo = uri.getUserInfo();
    if (userInfo != null) {
      String value = BaseEncoding.base64Url().encode(userInfo.getBytes(UTF_8));
      request.headers().set(HttpHeaderNames.AUTHORIZATION, "Basic " + value);
      return;
    }
    if (credentials == null || !credentials.hasRequestMetadata()) {
      return;
    }
    Map<String, List<String>> authHeaders = credentials.getRequestMetadata(uri);
    if (authHeaders == null || authHeaders.isEmpty()) {
      return;
    }
    for (Map.Entry<String, List<String>> entry : authHeaders.entrySet()) {
      String name = entry.getKey();
      for (String value : entry.getValue()) {
        request.headers().add(name, value);
      }
    }
  }

  protected void addExtraRemoteHeaders(HttpRequest request) {
    for (Map.Entry<String, String> header : extraHttpHeaders) {
      request.headers().add(header.getKey(), header.getValue());
    }
  }

  protected void addUserAgentHeader(HttpRequest request) {
    request.headers().set(HttpHeaderNames.USER_AGENT, USER_AGENT_VALUE);
  }

  protected String constructPath(URI uri, String hash, boolean isCas) {
    StringBuilder builder = new StringBuilder();
    builder.append(uri.getPath());
    if (!uri.getPath().endsWith("/")) {
      builder.append("/");
    }
    builder.append(isCas ? HttpCacheClient.CAS_PREFIX : HttpCacheClient.AC_PREFIX);
    builder.append(hash);
    return builder.toString();
  }

  protected String constructHost(URI uri) {
    boolean includePort =
        (uri.getPort() > 0)
            && ((uri.getScheme().equals("http") && uri.getPort() != 80)
                || (uri.getScheme().equals("https") && uri.getPort() != 443));
    return uri.getHost() + (includePort ? ":" + uri.getPort() : "");
  }

  @Override
  public void exceptionCaught(ChannelHandlerContext ctx, Throwable t) {
    failAndResetUserPromise(t);
    ctx.fireExceptionCaught(t);
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  @Override
  public void bind(ChannelHandlerContext ctx, SocketAddress localAddress, ChannelPromise promise) {
    ctx.bind(localAddress, promise);
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  @Override
  public void connect(
      ChannelHandlerContext ctx,
      SocketAddress remoteAddress,
      SocketAddress localAddress,
      ChannelPromise promise) {
    ctx.connect(remoteAddress, localAddress, promise);
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  @Override
  public void disconnect(ChannelHandlerContext ctx, ChannelPromise promise) {
    failAndResetUserPromise(new ClosedChannelException());
    ctx.disconnect(promise);
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  @Override
  public void close(ChannelHandlerContext ctx, ChannelPromise promise) {
    failAndResetUserPromise(new ClosedChannelException());
    ctx.close(promise);
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  @Override
  public void deregister(ChannelHandlerContext ctx, ChannelPromise promise) {
    failAndResetUserPromise(new ClosedChannelException());
    ctx.deregister(promise);
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  @Override
  public void read(ChannelHandlerContext ctx) {
    ctx.read();
  }

  @SuppressWarnings("FutureReturnValueIgnored")
  @Override
  public void flush(ChannelHandlerContext ctx) {
    ctx.flush();
  }

  @Override
  public void channelInactive(ChannelHandlerContext ctx) {
    failAndResetUserPromise(new ClosedChannelException());
    ctx.fireChannelInactive();
  }

  @Override
  public void handlerRemoved(ChannelHandlerContext ctx) {
    failAndResetUserPromise(new IOException("handler removed"));
  }

  @Override
  public void channelUnregistered(ChannelHandlerContext ctx) {
    failAndResetUserPromise(new ClosedChannelException());
    ctx.fireChannelUnregistered();
  }
}
