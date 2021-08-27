#include "iota_streams/channels.h"
#include <stdio.h>
#include <time.h>
#include <assert.h>

void rand_seed(char *seed, size_t n)
{
  static char const alphabet[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-=_+";

  if (seed && n)
  for(; --n; )
  {
    int key = rand() % (sizeof(alphabet) - 1);
    *seed++ = alphabet[key];
  }
  *seed = '\0';
}

int main()
{
  err_t e = ERR_OK;

  transport_t *tsp = NULL;

  // Implementation type:
  // 0: Single Branch
  // 1: Multi Branch
  // 2: Single Depth
  // _: Single Branch
  uint8_t implementation_type = 1;
  author_t *auth = NULL;
  address_t const *ann_link = NULL;
  subscriber_t *subA = NULL;
  subscriber_t *subB = NULL;
  subscriber_t *subC = NULL;

  message_links_t keyload_links = { NULL, NULL };
  message_links_t signed_packet_links = { NULL, NULL };
  message_links_t tagged_packet_links = { NULL, NULL };

  author_t *recovered_auth = NULL;
  address_t const *recovered_state_link = NULL;
  address_t const *original_state_link = NULL;
  address_t const *original_sub_state_link = NULL;
  address_t const *reset_sub_state_link = NULL;
  user_state_t const *recovered_auth_state = NULL;
  user_state_t const *original_auth_state = NULL;
  user_state_t const *original_sub_state = NULL;
  user_state_t const *reset_sub_state = NULL;

  public_key_t const *recovered_auth_pk = NULL;
  public_key_t const *original_auth_pk = NULL;
  public_key_t const *sub_a_pk = NULL;
  char const *recovered_link_id = NULL;
  char const *original_link_id = NULL;

  printf("Starting c bindings test\n\n");
  uint8_t multi_branching = 1;
  char seed[] = "bindings test seed";

#ifdef IOTA_STREAMS_CHANNELS_CLIENT
  char const *env_url = getenv("URL");
  char const *url = env_url ? env_url : "https://chrysalis-nodes.iota.org";

  srand((unsigned int)time(NULL));
  rand_seed(seed, sizeof(seed));

  printf("Using node: %s\n\n", url);
  tsp = transport_client_new_from_url(url);
#else
  printf("Using bucket transport (offline) \n\n");
  tsp = transport_new();
#endif
  printf("Making author with seed '%s'... ", seed);
  e = auth_new(&auth, seed, implementation_type, tsp);
  printf("%s\n", !e ? "done" : "failed");
  if(e) goto cleanup;

  // Fetch Application instance
  {
    channel_address_t const *appinst = NULL;
    public_key_t const *auth_pk = NULL;
    e = auth_channel_address(&appinst, auth);
    if(e) goto cleanup;
    // `auth_channel_address` does not allocate, no need to drop `appinst`
    char const *appinst_str = get_channel_address_str(appinst);
    printf("Channel address '%s'\n", appinst_str);
    drop_str(appinst_str);
    uint8_t flag = 0;
    e = auth_is_multi_branching(&flag, auth);
    if(e) goto cleanup;
    e = auth_get_public_key(&auth_pk, auth);
    if(e) goto cleanup;
  }
  printf("\n");
  if(e) goto cleanup;

  // Announcement
  {
    printf("Sending announcement... ");
    e = auth_send_announce(&ann_link, auth);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup;

    {
      char const *ann_address_inst_str = NULL;
      char const *ann_address_id_str = NULL;
      address_t *ann_link_copy = NULL;
      char const *ann_cpy_inst_str = NULL;
      char const *ann_cpy_id_str = NULL;
      char const *link_index = NULL;

#ifdef IOTA_STREAMS_CHANNELS_CLIENT
      transport_details_t details;
      printf("Getting announcement link details... ");
      e = transport_get_link_details(&details, tsp, ann_link);
      printf("%s\n", !e ? "done" : "failed");
      if(e) goto cleanup0;
      printf("  message_id: '%s'\n", details.msg_metadata.message_id);
      printf("  milestone: '%s'\n", details.milestone.message_id);
#endif

      // Test conversions
      printf("Converting announcement link to string... \n");
      ann_address_inst_str = get_address_inst_str(ann_link);
      ann_address_id_str = get_address_id_str(ann_link);
      // printf("  appinst: '%s'\n", ann_address_inst_str);
      // printf("  msgid  : '%s'\n", ann_address_id_str);

      char const connector[] = ":";
      char buffer[200];
      assert(strlen(ann_address_inst_str) + strlen(ann_address_id_str) + 1 <= sizeof(buffer));
      buffer[0] = '\0';
      strcat(buffer, ann_address_inst_str);
      strcat(buffer, connector);
      strcat(buffer, ann_address_id_str);
      printf("  '%s'\n", buffer);

      ann_link_copy = address_from_string(buffer);
      ann_cpy_inst_str = get_address_inst_str(ann_link_copy);
      ann_cpy_id_str = get_address_id_str(ann_link_copy);

      if(0
          || 0 != strcmp(ann_address_inst_str, ann_cpy_inst_str)
          || 0 != strcmp(ann_address_id_str, ann_cpy_id_str)
        ) {
        e = ERR_OPERATION_FAILED;
        goto cleanup0;
      }

      printf("Converting announcement link to tangle index... \n");
      link_index = get_address_index_str(ann_link_copy);
      printf("  '%s'\n", link_index);

cleanup0:
      drop_str(link_index);
      drop_str(ann_cpy_id_str);
      drop_str(ann_cpy_inst_str);
      drop_address(ann_link_copy);
      drop_str(ann_address_id_str);
      drop_str(ann_address_inst_str);
    }
    printf("\n");

    // Subscriber
    char const subA_seed[] = "SUBSCRIBERA9SEED";
    printf("Making SubA with seed '%s'... ", subA_seed);
    e = sub_new(&subA, subA_seed, tsp);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup;

    char const subB_seed[] = "SUBSCRIBERB9SEED";
    printf("Making SubB with seed '%s'... ", subB_seed);
    e = sub_new(&subB, subB_seed, tsp);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup;

    char const subC_seed[] = "SUBSCRIBERC9SEED";
    printf("Making SubC with seed '%s'... ", subC_seed);
    e = sub_new(&subC, subC_seed, tsp);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup;

    printf("SubA unwrapping announcement... ");
    e = sub_receive_announce(subA, ann_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup;
    printf("SubB unwrapping announcement... ");
    e = sub_receive_announce(subB, ann_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup;
    printf("SubC unwrapping announcement... ");
    e = sub_receive_announce(subC, ann_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup;

    // Collect Subscriber A state for comparison later
    printf("Retrieving link from subscriber A state for later comparison");
    e = sub_fetch_state(&original_sub_state, subA);
    if(e) goto cleanup;
    e = sub_get_public_key(&sub_a_pk, subA);
    original_sub_state_link = get_link_from_state(original_sub_state, sub_a_pk);
  }
  printf("\n");
  if(e) goto cleanup;

  // Subscribe
  {
    address_t const *subA_link = NULL;
    address_t const *subB_link = NULL;
    psk_id_t const *pskidC_auth = NULL;
    psk_id_t const *pskidC_subC = NULL;

    printf("SubA sending subscribe... ");
    e = sub_send_subscribe(&subA_link, subA, ann_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup1;
    printf("SubB sending subscribe... ");
    e = sub_send_subscribe(&subB_link, subB, ann_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup1;

    printf("Author accepting SubA subscription... ");
    e = auth_receive_subscribe(auth, subA_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup1;
    printf("Author accepting SubB subscription... ");
    e = auth_receive_subscribe(auth, subB_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup1;
    e = auth_store_psk(&pskidC_auth, auth, "SubC_psk_seed");
    if(e) goto cleanup1;
    e = sub_store_psk(&pskidC_subC, subC, "SubC_psk_seed");
    if(e) goto cleanup1;
cleanup1:
    drop_pskid(pskidC_subC);
    drop_pskid(pskidC_auth);
    drop_address(subB_link);
    drop_address(subA_link);
  }
  printf("\n");
  if(e) goto cleanup;

  // Keyload
  {
    address_t const *keyload_link = NULL;

    printf("Author sending keyload... ");
    e = auth_send_keyload_for_everyone(&keyload_links, auth, ann_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup2;

    printf("SubA receiving seq... ");
    address_t const *keyload_packet_sequence_link = keyload_links.seq_link;
    e = sub_receive_sequence(&keyload_link, subA, keyload_packet_sequence_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup2;

    printf("SubA receiving keyload... ");
    e = sub_receive_keyload(subA, keyload_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup2;

cleanup2:
    drop_address(keyload_link);
  }
  printf("\n");
  if(e) goto cleanup;

  // Fetch next message ids and process keyload - Sub B
  {
    next_msg_ids_t const *msg_ids = NULL;
    message_links_t subB_received_links = { NULL, NULL };

    printf("SubB generating next message ids... ");
    e = sub_gen_next_msg_ids(&msg_ids, subB);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup3;

    printf("SubB receiving keyload from ids... ");
    e = sub_receive_keyload_from_ids(&subB_received_links, subB, msg_ids);
    printf("%s\n", msg_ids ? "done" : "failed");
    if(msg_ids) goto cleanup3;

cleanup3:
    drop_links(subB_received_links);
    drop_next_msg_ids(msg_ids);
  }
  printf("\n");
  if(e) goto cleanup;

  // Fetch next message ids and process keyload - Sub C
  {
    next_msg_ids_t const *msg_ids = NULL;
    message_links_t subC_received_links = { NULL, NULL };

    printf("SubC generating next message ids... ");
    e = sub_gen_next_msg_ids(&msg_ids, subC);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup31;

    printf("SubC receiving keyload from ids... ");
    e = sub_receive_keyload_from_ids(&subC_received_links, subC, msg_ids);
    printf("%s\n", msg_ids ? "done" : "failed");
    if(msg_ids) goto cleanup31;

cleanup31:
    drop_links(subC_received_links);
    drop_next_msg_ids(msg_ids);
  }
  printf("\n");
  if(e) goto cleanup;

  char const public_payload[] = "A public payload woopeee";
  char const masked_payload[] = "A masked payload uhu";

  // Signed packet
  {
    printf("Author sending signed packet... ");
    e = auth_send_signed_packet(
      &signed_packet_links,
      auth, keyload_links,
      (uint8_t const *)public_payload, sizeof(public_payload),
      (uint8_t const *)masked_payload, sizeof(masked_payload));
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup;
  }

  {
    address_t const *signed_packet_address = NULL;
    packet_payloads_t signed_packet_response = { { NULL, 0, 0 }, { NULL, 0, 0 } };

    printf("SubA receiving seq... ");
    address_t const *signed_packet_sequence_link = signed_packet_links.seq_link;
    e = sub_receive_sequence(&signed_packet_address, subA, signed_packet_sequence_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup4;

    printf("SubA receiving signed packet... ");
    // memset(&signed_packet_response, 0, sizeof(signed_packet_response));
    e = sub_receive_signed_packet(&signed_packet_response, subA, signed_packet_address);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup4;
    printf("  public: '%s'\n", signed_packet_response.public_payload.ptr);
    printf("  masked: '%s'\n", signed_packet_response.masked_payload.ptr);

cleanup4:
    drop_payloads(signed_packet_response);
    drop_address(signed_packet_address);
  }
  printf("\n");
  if(e) goto cleanup;

  {
    address_t const *signed_packet_address = NULL;
    packet_payloads_t signed_packet_response = { { NULL, 0, 0 }, { NULL, 0, 0 } };

    printf("SubC receiving seq... ");
    address_t const *signed_packet_sequence_link = signed_packet_links.seq_link;
    e = sub_receive_sequence(&signed_packet_address, subC, signed_packet_sequence_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup41;

    printf("SubC receiving signed packet... ");
    // memset(&signed_packet_response, 0, sizeof(signed_packet_response));
    e = sub_receive_signed_packet(&signed_packet_response, subC, signed_packet_address);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup41;
    printf("  public: '%s'\n", signed_packet_response.public_payload.ptr);
    printf("  masked: '%s'\n", signed_packet_response.masked_payload.ptr);

cleanup41:
    drop_payloads(signed_packet_response);
    drop_address(signed_packet_address);
  }
  printf("\n");
  if(e) goto cleanup;

  // Tagged packet
  {
    address_t const *tagged_packet_address = NULL;
    packet_payloads_t tagged_packet_response = { { NULL, 0, 0 }, { NULL, 0, 0 } };

    printf("Author sending tagged packet... ");
    e = auth_send_tagged_packet(
      &tagged_packet_links,
      auth, signed_packet_links,
      (uint8_t const *)public_payload, sizeof(public_payload),
      (uint8_t const *)masked_payload, sizeof(masked_payload));
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup5;

    printf("SubA receiving seq... ");
    address_t const *tagged_packet_sequence_link = tagged_packet_links.seq_link;
    e = sub_receive_sequence(&tagged_packet_address, subA, tagged_packet_sequence_link);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup5;

    printf("Subscriber receiving tagged packet... ");
    e = sub_receive_tagged_packet(&tagged_packet_response, subA, tagged_packet_address);
    printf("%s\n", !e ? "done" : "failed");
    if(e) goto cleanup5;
    printf("  public: '%s'\n", tagged_packet_response.public_payload.ptr);
    printf("  masked: '%s'\n", tagged_packet_response.masked_payload.ptr);

cleanup5:
    drop_payloads(tagged_packet_response);
    drop_address(tagged_packet_address);
  }
  printf("\n");
  if(e) goto cleanup;

  {
    message_links_t tagged_packet_1_links = { NULL, NULL };
    message_links_t tagged_packet_2_links = { NULL, NULL };
    message_links_t tagged_packet_3_links = { NULL, NULL };

    printf("Author sending 3 tagged packets... \n");
    char const public_1[] = "Public 111";
    char const public_2[] = "Public 22";
    char const public_3[] = "Public 3";
    char const masked_1[] = "Masked 1";
    char const masked_2[] = "Masked 22";
    char const masked_3[] = "Masked 333";
    e = auth_send_tagged_packet(
      &tagged_packet_1_links, auth, tagged_packet_links,
      (uint8_t const *)public_1, sizeof(public_1),
      (uint8_t const *)masked_1, sizeof(masked_1));
    printf("  (1) %s\n", !e ? "done" : "failed");
    printf("  (1) public: '%s'\n", public_1);
    printf("  (1) masked: '%s'\n", masked_1);
    if(e) goto cleanup6;
    e = auth_send_tagged_packet(
      &tagged_packet_1_links, auth, tagged_packet_links,
      (uint8_t const *)public_2, sizeof(public_2),
      (uint8_t const *)masked_2, sizeof(masked_2));
    printf("  (2) %s\n", !e ? "done" : "failed");
    printf("  (2) public: '%s'\n", public_2);
    printf("  (2) masked: '%s'\n", masked_2);
    if(e) goto cleanup6;
    e = auth_send_tagged_packet(
      &tagged_packet_1_links, auth, tagged_packet_links,
      (uint8_t const *)public_3, sizeof(public_3),
      (uint8_t const *)masked_3, sizeof(masked_3));
    printf("  (3) %s\n", !e ? "done" : "failed");
    printf("  (3) public: '%s'\n", public_3);
    printf("  (3) masked: '%s'\n", masked_3);
    if(e) goto cleanup6;

cleanup6:
    drop_links(tagged_packet_3_links);
    drop_links(tagged_packet_2_links);
    drop_links(tagged_packet_1_links);
  }
  printf("\n");
  if(e) goto cleanup;

  {
    unwrapped_messages_t const *message_returns = NULL;

    printf("SubA syncing state... ");
    e = sub_sync_state(&message_returns, subA);
    printf("  %s\n", !e ? "done" : "failed");
    if(e) goto cleanup;

    size_t i;
    for(i = 0; i < get_payloads_count(message_returns); i++)
    {
      packet_payloads_t response = get_indexed_payload(message_returns, i);
      printf("  (%zu) public: '%s'\n", i, response.public_payload.ptr);
      printf("  (%zu) masked: '%s'\n", i, response.masked_payload.ptr);
      //`get_indexed_payload` does not allocate, no need to drop `response`
    }

cleanup7:
    drop_unwrapped_messages(message_returns);
  }
  printf("\n");
  if(e) goto cleanup;

  {
    author_t *recovered_auth = NULL;
    user_state_t const *recovered_auth_state = NULL;
    user_state_t const *original_auth_state = NULL;
    address_t const *recovered_state_link = NULL;
    address_t const *original_state_link = NULL;
    unwrapped_messages_t const *message_returns = NULL;

    printf("Recovering author... ");
    e = auth_recover(&recovered_auth, seed, ann_link, implementation_type, tsp);
    printf("  %s\n", !e ? "done" : "failed");
    if(e) goto cleanup8;

    e = auth_fetch_state(&recovered_auth_state, recovered_auth);
    if(e) goto cleanup8;
    e = auth_fetch_state(&original_auth_state, auth);
    if(e) goto cleanup8;
    assert(recovered_auth_state);
    assert(original_auth_state);

    public_key_t const *recovered_auth_pk = NULL;
    e = auth_get_public_key(&recovered_auth_pk, recovered_auth);
    if(e) goto cleanup8;
    public_key_t const *original_auth_pk = NULL;
    e = auth_get_public_key(&original_auth_pk, auth);
    if(e) goto cleanup8;
    assert(recovered_auth_pk);
    assert(original_auth_pk);

    recovered_state_link = get_link_from_state(recovered_auth_state, recovered_auth_pk);
    original_state_link = get_link_from_state(original_auth_state, original_auth_pk);
    assert(recovered_state_link);
    assert(original_state_link);

    char const *recovered_link_id = get_address_id_str(recovered_state_link);
    char const *original_link_id = get_address_id_str(original_state_link);

    printf("  recovered state link: '%s'\n", recovered_link_id);
    printf("  original  state link: '%s'\n", original_link_id);

    printf("Author fetching previous messages... ");
    e = auth_fetch_prev_msgs(&message_returns, auth, recovered_state_link, 3);
    printf("  %s\n", !e ? "done" : "failed");
    if(e) goto cleanup;

cleanup8:
    drop_address(original_state_link);
    drop_address(recovered_state_link);
    drop_user_state(original_auth_state);
    drop_user_state(recovered_auth_state);
    auth_drop(recovered_auth);
    drop_unwrapped_messages(message_returns);
  }
  printf("\n");
  if(e) goto cleanup;

  {
    buffer_t bytes = { NULL, 0, 0 };
    author_t *auth_new = NULL;

    printf("Exporting author state... ");
    e = auth_export(&bytes, auth, "my_password");
    printf("  %s\n", !e ? "done" : "failed");
    if(e) goto cleanup9;

    printf("Importing author state... ");
    e = auth_import(&auth_new, bytes, "my_password", tsp);
    printf("  %s\n", !e ? "done" : "failed");
    if(e) goto cleanup9;
    //auth_import consumes bytes, need to clear to avoid double-free
    bytes.ptr = NULL;

 cleanup9:
    auth_drop(auth_new);
    drop_buffer(bytes);
  }
  printf("\n");
  if(e) goto cleanup;

  {
    printf("Resetting subscriber state... ");
    e = sub_reset_state(subA);
    if(e) goto cleanup;
    printf("Fetching subscriber state... ");
    e = sub_fetch_state(&reset_sub_state, subA);
    if(e) goto cleanup10;
    reset_sub_state_link = get_link_from_state(reset_sub_state, sub_a_pk);

    char const *reset_state_link_id = get_address_id_str(reset_sub_state_link);
    char const *original_state_link_id = get_address_id_str(original_sub_state_link);

    printf("  reset sub state link: '%s'\n", reset_state_link_id);
    printf("  original  state link: '%s'\n", original_state_link_id);
  }
  printf("\n");
  if(e) goto cleanup;

cleanup10:
  drop_user_state(reset_sub_state);
  drop_address(reset_sub_state_link);

cleanup:
  drop_links(tagged_packet_links);
  drop_links(signed_packet_links);
  drop_links(keyload_links);
  sub_drop(subC);
  sub_drop(subB);
  sub_drop(subA);

  drop_address(ann_link);
  auth_drop(auth);
  transport_drop(tsp);
  drop_user_state(original_sub_state);
  drop_address(original_sub_state_link);

  printf("Error code: %d\n", e);
  if(e != ERR_OK) {
    char const *err_msg = get_last_error();
    printf("Failed with error: %s\n", err_msg);
    drop_str(err_msg);
  }

  return (e == ERR_OK ? 0 : 1);
}
