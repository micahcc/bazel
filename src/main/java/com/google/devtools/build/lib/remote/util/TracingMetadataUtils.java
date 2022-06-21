// Copyright 2017 The Bazel Authors. All rights reserved.
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
package com.google.devtools.build.lib.remote.util;

import build.bazel.remote.execution.v2.RequestMetadata;
import build.bazel.remote.execution.v2.ToolDetails;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Preconditions;
import com.google.devtools.build.lib.actions.ActionExecutionMetadata;
import com.google.devtools.build.lib.analysis.BlazeVersionInfo;
import com.google.devtools.build.lib.cmdline.Label;
import com.google.devtools.build.lib.remote.options.RemoteOptions;
import io.grpc.ClientInterceptor;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCall.Listener;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.protobuf.ProtoUtils;
import io.grpc.stub.MetadataUtils;
import java.util.List;
import java.util.Map.Entry;
import javax.annotation.Nullable;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import io.grpc.ForwardingClientCall.SimpleForwardingClientCall;
import io.grpc.ClientCall;
import io.grpc.MethodDescriptor;
import io.grpc.CallOptions;
import io.grpc.Channel;
import java.util.Base64;
import java.util.Calendar;
import java.text.SimpleDateFormat;
import java.util.Locale;
import java.util.TimeZone;


final class AwsCredentialsClientInterceptor implements ClientInterceptor {

    private final String awsId;
    private final String awsSecret;

    static private String hmacSha1(String key, String data) {

        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            SecretKeySpec secret = new SecretKeySpec(key.getBytes(),"HmacSHA1");
            mac.init(secret);
            byte[] digest = mac.doFinal(data.getBytes());
            String out = Base64.getEncoder().encodeToString(digest);
            System.out.println(key);
            System.out.println(data);
            System.out.println(out);
            return out;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    static private String getServerTime() {
        Calendar calendar = Calendar.getInstance();
        SimpleDateFormat dateFormat = new SimpleDateFormat(
                "EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
        dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
        return dateFormat.format(calendar.getTime());
    }


    // Non private to avoid synthetic class
    AwsCredentialsClientInterceptor(String awsId, String awsSecret) {
      Preconditions.checkNotNull(awsId);
      Preconditions.checkNotNull(awsSecret);
      this.awsId = awsId;
      this.awsSecret = awsSecret;
    }

    @Override
    public <ReqT, RespT> ClientCall<ReqT, RespT> interceptCall(
            MethodDescriptor<ReqT, RespT> method, CallOptions callOptions, Channel next) {
            System.out.println(method);
            System.out.println(callOptions);
            System.out.println(next);
        return new HeaderAttachingClientCall<>(next.newCall(method, callOptions));
            }

    private final class HeaderAttachingClientCall<ReqT, RespT>
            extends SimpleForwardingClientCall<ReqT, RespT> {

            //private final String method;
            //private final String uri;

            // Non private to avoid synthetic class
            HeaderAttachingClientCall(ClientCall<ReqT, RespT> call) {
                super(call);
            }

            @Override
            public void start(Listener<RespT> responseListener, Metadata headers) {
            System.out.println(headers);

                // add header:
                // x-amz-date
                String dateStr = getServerTime();
                headers.put( Metadata.Key.of("x-amz-date", Metadata.ASCII_STRING_MARSHALLER),dateStr);

                String toHash;
                 //   StringToSign = HTTP-Verb + "\n" +
                 //   Content-MD5 + "\n" +
                 //   Content-Type + "\n" +
                 //   Date + "\n" +
                 //   CanonicalizedAmzHeaders +
                 //   CanonicalizedResource;

                String method = "GET";
                String uri = "/hello";
                if(method == "GET") {
                    // GET\n
                    // \n
                    // \n
                    // Tue, 27 Mar 2007 19:36:42 +0000\n
                    // /photos/blob
                    toHash = "GET\n\n\n" + dateStr + uri;
                } else if(method == "PUT") {
                 // PUT\n
                 // \n
                 // application/octet-stream\n
                 // Tue, 27 Mar 2007 21:15:45 +0000\n
                 // /photos/blob
                 toHash = "PUT\n\napplication/octet-stream\n" + dateStr + uri;
                }  else {
                    toHash = "";
                }

                System.out.println(toHash);
                String sigStr = hmacSha1(awsSecret, toHash);
                // Signature = Base64(
                //  HMAC-SHA1(
                //     UTF-8-Encoding-Of(YourSecretAccessKey),
                //     UTF-8-Encoding-Of( StringToSign )
                //  )
                // );
                // Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature;
                System.out.println("AWS + " + awsId + ":" + sigStr);

                headers.put( Metadata.Key.of("AWS " + awsId, Metadata.ASCII_STRING_MARSHALLER), sigStr);
                super.start(responseListener, headers);
            }
    }
}

/** Utility functions to handle Metadata for remote Grpc calls. */
public class TracingMetadataUtils {

  private TracingMetadataUtils() {}

  private static final Context.Key<RequestMetadata> CONTEXT_KEY =
      Context.key("remote-grpc-metadata");

  @VisibleForTesting
  public static final Metadata.Key<RequestMetadata> METADATA_KEY =
      ProtoUtils.keyForProto(RequestMetadata.getDefaultInstance());

  public static RequestMetadata buildMetadata(
      String buildRequestId,
      String commandId,
      String actionId,
      @Nullable ActionExecutionMetadata actionMetadata) {
    Preconditions.checkNotNull(buildRequestId);
    Preconditions.checkNotNull(commandId);
    Preconditions.checkNotNull(actionId);
    RequestMetadata.Builder builder =
        RequestMetadata.newBuilder()
            .setCorrelatedInvocationsId(buildRequestId)
            .setToolInvocationId(commandId)
            .setActionId(actionId)
            .setToolDetails(
                ToolDetails.newBuilder()
                    .setToolName("bazel")
                    .setToolVersion(BlazeVersionInfo.instance().getVersion()));
    if (actionMetadata != null) {
      builder.setActionMnemonic(actionMetadata.getMnemonic());
      Label label = actionMetadata.getOwner().getLabel();
      if (label != null) {
        builder.setTargetId(label.getCanonicalForm());
      }
      builder.setConfigurationId(actionMetadata.getOwner().getConfigurationChecksum());
    }
    return builder.build();
  }

  /**
   * Fetches a {@link RequestMetadata} defined on the current context.
   *
   * @throws IllegalStateException when the metadata is not defined in the current context.
   */
  public static RequestMetadata fromCurrentContext() {
    RequestMetadata metadata = CONTEXT_KEY.get();
    if (metadata == null) {
      throw new IllegalStateException("RequestMetadata not set in current context.");
    }
    return metadata;
  }

  /** Creates a {@link Metadata} containing the {@link RequestMetadata}. */
  public static Metadata headersFromRequestMetadata(RequestMetadata requestMetadata) {
    Metadata headers = new Metadata();
    headers.put(METADATA_KEY, requestMetadata);
    return headers;
  }

  /**
   * Extracts a {@link RequestMetadata} from a {@link Metadata} and returns it if it exists. If it
   * does not exist, returns {@code null}.
   */
  @Nullable
  public static RequestMetadata requestMetadataFromHeaders(Metadata headers) {
    return headers.get(METADATA_KEY);
  }

  public static ClientInterceptor attachMetadataInterceptor(RequestMetadata requestMetadata) {
    return MetadataUtils.newAttachHeadersInterceptor(headersFromRequestMetadata(requestMetadata));
  }


  public static ClientInterceptor newAwsHeadersInterceptor(RemoteOptions options) {
        return new AwsCredentialsClientInterceptor(options.remoteCacheAwsId, options.remoteCacheAwsSecret);
  }

  private static Metadata newMetadataForHeaders(List<Entry<String, String>> headers) {
    Metadata metadata = new Metadata();
    headers.forEach(
        header ->
            metadata.put(
                Metadata.Key.of(header.getKey(), Metadata.ASCII_STRING_MARSHALLER),
                header.getValue()));
    return metadata;
  }

  public static ClientInterceptor newCacheHeadersInterceptor(RemoteOptions options) {
    Metadata metadata = newMetadataForHeaders(options.remoteHeaders);
    metadata.merge(newMetadataForHeaders(options.remoteCacheHeaders));
    return MetadataUtils.newAttachHeadersInterceptor(metadata);
  }

  public static ClientInterceptor newDownloaderHeadersInterceptor(RemoteOptions options) {
    Metadata metadata = newMetadataForHeaders(options.remoteHeaders);
    metadata.merge(newMetadataForHeaders(options.remoteDownloaderHeaders));
    return MetadataUtils.newAttachHeadersInterceptor(metadata);
  }

  public static ClientInterceptor newExecHeadersInterceptor(RemoteOptions options) {
    Metadata metadata = newMetadataForHeaders(options.remoteHeaders);
    metadata.merge(newMetadataForHeaders(options.remoteExecHeaders));
    return MetadataUtils.newAttachHeadersInterceptor(metadata);
  }

  /** GRPC interceptor to add logging metadata to the GRPC context. */
  public static class ServerHeadersInterceptor implements ServerInterceptor {
    @Override
    public <ReqT, RespT> Listener<ReqT> interceptCall(
        ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
      RequestMetadata meta = requestMetadataFromHeaders(headers);
      if (meta == null) {
        throw io.grpc.Status.INVALID_ARGUMENT
            .withDescription(
                "RequestMetadata not received from the client for "
                    + call.getMethodDescriptor().getFullMethodName())
            .asRuntimeException();
      }
      Context ctx = Context.current().withValue(CONTEXT_KEY, meta);
      return Contexts.interceptCall(ctx, call, headers, next);
    }
  }
}
