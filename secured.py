def secure_verify():
	f = open(__file__, "rb")
	text = f.read()
	f.close()
	from hashes import hashes, calls
	return verify_integrity() and False not in (specific_hash(text, key) == hashes[key] for key in calls.keys())


def get_hashes():
	f = open(__file__, "rb")
	text = f.read()
	f.close()
	from hashes import hashes, calls
	return [specific_hash(text, key) for key in calls.keys()]


def specific_hash(text, func):
	import hashlib
	m = hashlib.new(func)
	m.update(text)
	return m.hexdigest()
