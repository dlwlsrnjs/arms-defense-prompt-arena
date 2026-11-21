from scripts import assist_memjack_gpu0 as helper

def test_secondary_attempt_namespace_does_not_collide_with_primary_gpu1(tmp_path):
 (tmp_path/'attempt-001-gpu1').mkdir()
 (tmp_path/'attempt-002-gpu1').mkdir()
 assert helper.choose_attempt(tmp_path)==1001
 (tmp_path/'attempt-1001-gpu0').mkdir()
 assert helper.choose_attempt(tmp_path)==1002
