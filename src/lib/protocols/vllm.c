/*
 * vllm.c
 *
 * Copyright (C) 2026 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "ndpi_protocol_ids.h"

#define NDPI_CURRENT_PROTO NDPI_PROTOCOL_VLLM

#include "ndpi_api.h"
#include "ndpi_private.h"

/* vLLM - high-performance LLM inference server
   Default port: 8000 (configurable)
   OpenAI-compatible API:
   - GET /v1/models → model listing in OpenAI format
   - POST /v1/chat/completions, POST /v1/completions
   - GET /health → {"status":"ok"}
   Detection: "vllm" in response body (model metadata, error messages, headers)
   Avoid false positives with actual OpenAI: check host is NOT openai.com */

static void ndpi_search_vllm(struct ndpi_detection_module_struct *ndpi_struct,
                              struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &ndpi_struct->packet;
  const char *payload_str = (const char *)packet->payload;
  u_int16_t payload_len = packet->payload_packet_len;

  NDPI_LOG_DBG(ndpi_struct, "search vLLM\n");

  /* Helper: extract model name from JSON body */
  #define EXTRACT_VLLM_MODEL() do { \
    if(payload_len > 10) { \
      const char *m = ndpi_strnstr(payload_str, "\"model\":\"", payload_len); \
      if(m == NULL) m = ndpi_strnstr(payload_str, "\"model_name\":\"", payload_len); \
      if(m != NULL) { \
        const char *mv = m; \
        if(m[7] == '\"') mv = m + 9; /* "model":" */ \
        else mv = m + 13; /* "model_name":" */ \
        const char *me = ndpi_strnstr(mv, "\"", payload_len - (mv - payload_str)); \
        if(me != NULL) { \
          size_t mlen = me - mv; \
          if(mlen < sizeof(flow->protos.vllm.model_name)) { \
            memcpy(flow->protos.vllm.model_name, mv, mlen); \
            flow->protos.vllm.model_name[mlen] = '\0'; \
          } \
        } \
      } \
    } \
  } while(0)

  #define SAVE_VLLM_ACTION(name, nlen) do { \
    if(nlen < sizeof(flow->protos.vllm.api_action)) { \
      memcpy(flow->protos.vllm.api_action, name, nlen); \
      flow->protos.vllm.api_action[nlen] = '\0'; \
    } \
  } while(0)

  /* Case 1: vLLM over HTTP */
  if(flow->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
     flow->detected_protocol_stack[1] == NDPI_PROTOCOL_HTTP) {

    /* Check for "vllm" identifier in response body - most reliable */
    if(payload_len > 4 &&
       ndpi_strnstr(payload_str, "vllm", payload_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found vLLM (response body)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VLLM,
                                 NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
      return;
    }

    /* Check URL path for /v1/chat/completions or /v1/completions
       BUT only if host is NOT a known OpenAI domain (to avoid false positives) */
    if(packet->http_url_name.ptr != NULL && packet->http_url_name.len > 0 &&
       packet->host_line.ptr != NULL && packet->host_line.len > 0) {
      /* Exclude known OpenAI domains */
      if(ndpi_strnstr((const char *)packet->host_line.ptr, "openai.com",
                     packet->host_line.len) != NULL ||
         ndpi_strnstr((const char *)packet->host_line.ptr, "chatgpt.com",
                     packet->host_line.len) != NULL) {
        NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
        return;
      }

      const char *url = (const char *)packet->http_url_name.ptr;
      u_int16_t url_len = packet->http_url_name.len;
      int path_matched = 0;

      if(ndpi_strnstr(url, "/v1/chat/completions", url_len) != NULL) {
        SAVE_VLLM_ACTION("chat/completions", 16); path_matched = 1;
      } else if(ndpi_strnstr(url, "/v1/completions", url_len) != NULL) {
        SAVE_VLLM_ACTION("completions", 12); path_matched = 1;
      } else if(ndpi_strnstr(url, "/v1/embeddings", url_len) != NULL) {
        SAVE_VLLM_ACTION("embeddings", 10); path_matched = 1;
      }

      if(path_matched) {
        /* Additional check: content type must be JSON for API calls */
        if((packet->content_line.ptr != NULL &&
            LINE_ENDS(packet->content_line, "application/json")) ||
           (payload_len > 0 && packet->payload[0] == '{')) {
          EXTRACT_VLLM_MODEL();
          NDPI_LOG_INFO(ndpi_struct, "found vLLM (/v1/ URL path)\n");
          ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VLLM,
                                     NDPI_PROTOCOL_HTTP, NDPI_CONFIDENCE_DPI);
          return;
        }
      }
    }

    NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
    return;
  }

  /* Case 2: vLLM over raw TCP */
  if(packet->tcp != NULL && payload_len > 4) {
    /* Check for "vllm" in response body */
    if(ndpi_strnstr(payload_str, "vllm", payload_len) != NULL) {
      NDPI_LOG_INFO(ndpi_struct, "found vLLM (raw TCP)\n");
      ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_VLLM,
                                 NDPI_PROTOCOL_UNKNOWN, NDPI_CONFIDENCE_DPI);
      return;
    }
  }

  NDPI_EXCLUDE_DISSECTOR(ndpi_struct, flow);
  #undef EXTRACT_VLLM_MODEL
  #undef SAVE_VLLM_ACTION
}

void init_vllm_dissector(struct ndpi_detection_module_struct *ndpi_struct)
{
  ndpi_register_dissector("vLLM", ndpi_struct,
                     ndpi_search_vllm,
                     NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
                     1, NDPI_PROTOCOL_VLLM);
}