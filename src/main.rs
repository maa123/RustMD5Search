extern crate crypto;

use crypto::md5::Md5;
use crypto::digest::Digest;


const C_N :usize = 36;
const CHAR32S :[char;C_N] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'];

fn arr_from_hash(x :&str) -> [u8;16] {
	let mut db = [0 as u8; 16];
	let mut ct :char = '0';
	
	for (i, j) in x.chars().enumerate() {
		if i%2 == 1 {
			let st = ct.to_string() + &j.to_string();
			let p = u8::from_str_radix(&st, 16);
			db[i/2] = p.unwrap();
		} else {
			ct = j;
		}
	}

	db
}

fn radix36(mut x :u32) -> String {
	let mut res = String::with_capacity(10);
	
	loop{
		let y = x % 36;
		x = x / 36;
		res.push(CHAR32S[y as usize]);
		if x == 0 {
			break;
		}
	}

	res.chars().rev().collect::<String>()
}

fn search_hash(saltstr :&str, target :[u8; 16]) -> String {
	let salt = saltstr.as_bytes();

	let mut md5 = Md5::new();
	let mut ds = [0 as u8; 16];
	let mut res = String::new();
	let mut i = 0;
	
	while i < std::u32::MAX {
		md5.input(salt);
		md5.input(radix36(i).as_bytes());
		md5.result(&mut ds);
		if ds == target {
			res = radix36(i);
			break;
		}
		md5.reset();
		i += 1;
	}

	res
}

fn main(){
	let args :Vec<String> = std::env::args().collect();
	
	//TODO: エラー処理
	let salt = &args[1];
	let target = &args[2];
	
	//TODO: Thread
	let res = search_hash(salt, arr_from_hash(target));
	
	println!("結果:{}", res);
}

#[cfg(test)]
mod tests {
	use super::*;
	#[test]
	fn searchash() {
		assert_eq!("abcd", search_hash("1", arr_from_hash("2956486c175b34bfcca6973bf51b8d2a")));
	}
}
